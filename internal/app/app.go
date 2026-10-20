package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/rj9676564/certkeeper/internal/acme"
	"github.com/rj9676564/certkeeper/internal/certstore"
	"github.com/rj9676564/certkeeper/internal/config"
	"github.com/rj9676564/certkeeper/internal/lock"
	"github.com/rj9676564/certkeeper/internal/notify"
	"github.com/rj9676564/certkeeper/internal/reload"
)

type Issuer interface {
	Issue(ctx context.Context, req acme.IssueRequest) (*acme.Result, error)
}

type Notifier interface {
	Notify(ctx context.Context, event notify.Event, data notify.Data)
}

type Reloader interface {
	Run(ctx context.Context, commands []string) error
}

type Options struct {
	Config   *config.Config
	Staging  bool
	DryRun   bool
	Force    bool
	Domain   string
	Logger   *slog.Logger
	Issuer   Issuer
	Notifier Notifier
	Reloader Reloader
	Now      func() time.Time
}

type DomainResult struct {
	Domain    string    `json:"domain"`
	Action    string    `json:"action"`
	Reason    string    `json:"reason,omitempty"`
	DaysLeft  int       `json:"days_left,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Error     string    `json:"error,omitempty"`
}

type Summary struct {
	RunID   string         `json:"run_id"`
	Results []DomainResult `json:"results"`
	Renewed int            `json:"renewed"`
	Skipped int            `json:"skipped"`
	Failed  int            `json:"failed"`
	DryRun  bool           `json:"dry_run,omitempty"`
}

func (s *Summary) Err() error {
	var errs []error
	for _, result := range s.Results {
		if result.Error != "" {
			errs = append(errs, fmt.Errorf("%s: %s", result.Domain, result.Error))
		}
	}
	return errors.Join(errs...)
}

func Run(ctx context.Context, opts Options) (*Summary, error) {
	if opts.Config == nil {
		return nil, fmt.Errorf("config is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Issuer == nil {
		opts.Issuer = &acme.Manager{
			Directory: opts.Config.ACMEDirectory(opts.Staging),
			Email:     opts.Config.Email,
			StateDir:  opts.Config.Storage.StateDir,
			Logger:    opts.Logger,
		}
	}
	if opts.Notifier == nil {
		opts.Notifier = notify.New(opts.Config.Notify, opts.Logger)
	}
	if opts.Reloader == nil {
		opts.Reloader = reloadRunner(opts.Logger)
	}

	locker, err := lock.New(opts.Config.Storage.StateDir)
	if err != nil {
		return nil, err
	}
	lockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := locker.Lock(lockCtx); err != nil {
		return nil, err
	}
	defer func() { _ = locker.Unlock() }()

	domains, err := opts.Config.ResolveDomains()
	if err != nil {
		return nil, err
	}
	runID := newRunID()
	summary := &Summary{RunID: runID, DryRun: opts.DryRun}
	store := certstore.Store{
		CertMode: mustMode(opts.Config.Storage.CertMode, 0o644),
		KeyMode:  mustMode(opts.Config.Storage.KeyMode, 0o600),
		Backup:   opts.Config.Storage.Backup == nil || *opts.Config.Storage.Backup,
	}
	now := opts.Now()

	for _, domain := range domains {
		if opts.Domain != "" && !matchesDomain(domain, opts.Domain) {
			continue
		}
		result := processDomain(ctx, opts, store, domain, now)
		if result.Error != "" {
			summary.Failed++
			opts.Logger.Error("domain failed", "domain", result.Domain, "error", result.Error)
			opts.Notifier.Notify(ctx, notify.EventFailure, notify.Data{
				Status:      "failed",
				Domain:      result.Domain,
				Error:       result.Error,
				DNSProvider: domain.DNSProvider,
				RunID:       runID,
			})
		}
		if result.Action == "renewed" {
			summary.Renewed++
			opts.Notifier.Notify(ctx, notify.EventRenewed, notify.Data{
				Status:      "renewed",
				Domain:      result.Domain,
				ExpiresAt:   result.ExpiresAt.Format(time.RFC3339),
				DaysLeft:    result.DaysLeft,
				DNSProvider: domain.DNSProvider,
				RunID:       runID,
			})
		}
		if result.Action == "skipped" {
			summary.Skipped++
			opts.Notifier.Notify(ctx, notify.EventSkipped, notify.Data{
				Status:      "skipped",
				Domain:      result.Domain,
				ExpiresAt:   result.ExpiresAt.Format(time.RFC3339),
				DaysLeft:    result.DaysLeft,
				DNSProvider: domain.DNSProvider,
				RunID:       runID,
			})
		}
		summary.Results = append(summary.Results, result)
	}
	if len(summary.Results) == 0 {
		return nil, fmt.Errorf("no matching domains found")
	}
	if err := summary.Err(); err != nil {
		return summary, err
	}
	return summary, nil
}

func Check(ctx context.Context, cfg *config.Config, domainFilter string, now time.Time) (*Summary, error) {
	if now.IsZero() {
		now = time.Now()
	}
	domains, err := cfg.ResolveDomains()
	if err != nil {
		return nil, err
	}
	store := certstore.Store{}
	summary := &Summary{RunID: newRunID()}
	for _, domain := range domains {
		if domainFilter != "" && !matchesDomain(domain, domainFilter) {
			continue
		}
		result := DomainResult{Domain: domain.Name}
		existing, err := store.Load(domain.CertPath, domain.KeyPath)
		if err != nil {
			result.Action = "renew"
			result.Reason = err.Error()
			result.Error = err.Error()
			summary.Failed++
			summary.Results = append(summary.Results, result)
			continue
		}
		needs, reason, err := certstore.NeedsRenew(existing, domain.Names, domain.RenewBeforeDays, now)
		if err != nil {
			result.Action = "renew"
			result.Reason = err.Error()
			result.Error = err.Error()
			summary.Failed++
		} else if needs {
			result.Action = "renew"
			result.Reason = reason
			summary.Failed++
		} else {
			result.Action = "ok"
			result.Reason = reason
			summary.Skipped++
		}
		if existing != nil {
			result.ExpiresAt = existing.Cert.NotAfter
			result.DaysLeft = existing.DaysLeft
		}
		summary.Results = append(summary.Results, result)
	}
	if len(summary.Results) == 0 {
		return nil, fmt.Errorf("no matching domains found")
	}
	if summary.Failed > 0 {
		return summary, fmt.Errorf("%d domain(s) need attention", summary.Failed)
	}
	return summary, nil
}

func processDomain(ctx context.Context, opts Options, store certstore.Store, domain config.ResolvedDomain, now time.Time) DomainResult {
	result := DomainResult{Domain: domain.Name}
	opts.Logger.Info("checking domain", "domain", domain.Name, "provider", domain.DNSProvider)

	existing, err := store.Load(domain.CertPath, domain.KeyPath)
	if err != nil {
		opts.Logger.Warn("existing certificate is invalid, will renew", "domain", domain.Name, "error", err)
		existing = nil
	}
	needs, reason, checkErr := certstore.NeedsRenew(existing, domain.Names, domain.RenewBeforeDays, now)
	if checkErr != nil {
		result.Action = "failed"
		result.Error = checkErr.Error()
		return result
	}
	if existing != nil {
		result.ExpiresAt = existing.Cert.NotAfter
		result.DaysLeft = existing.DaysLeft
	}
	if !needs && !opts.Force {
		result.Action = "skipped"
		result.Reason = reason
		opts.Logger.Info("certificate is valid, skipping", "domain", domain.Name, "days_left", result.DaysLeft, "reason", reason)
		return result
	}
	if opts.DryRun {
		result.Action = "would-renew"
		result.Reason = reason
		opts.Logger.Info("dry run: certificate would be renewed", "domain", domain.Name, "reason", reason)
		return result
	}

	var existingKey []byte
	if existing != nil {
		existingKey = existing.KeyPEM
	}
	issued, err := opts.Issuer.Issue(ctx, acme.IssueRequest{
		Domains:        domain.Names,
		KeyType:        domain.KeyType,
		Credentials:    domain.Credentials,
		ExistingKeyPEM: existingKey,
	})
	if err != nil {
		result.Action = "failed"
		result.Error = err.Error()
		return result
	}
	cert, err := certstore.Verify(issued.CertificatePEM, issued.PrivateKeyPEM, domain.Names, now)
	if err != nil {
		result.Action = "failed"
		result.Error = "issued certificate is invalid: " + err.Error()
		return result
	}
	if err := store.Write(domain.CertPath, domain.KeyPath, issued.CertificatePEM, issued.PrivateKeyPEM); err != nil {
		result.Action = "failed"
		result.Error = err.Error()
		return result
	}
	result.Action = "renewed"
	result.Reason = "renewed"
	result.ExpiresAt = cert.NotAfter
	result.DaysLeft = int(cert.NotAfter.Sub(now).Hours() / 24)
	opts.Logger.Info("certificate renewed", "domain", domain.Name, "expires_at", cert.NotAfter.Format(time.RFC3339), "days_left", result.DaysLeft)

	if err := opts.Reloader.Run(ctx, domain.Reload); err != nil {
		result.Action = "failed"
		result.Error = "certificate renewed but reload failed: " + err.Error()
		return result
	}
	return result
}

func formatExpiry(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.RFC3339)
}

func matchesDomain(domain config.ResolvedDomain, filter string) bool {
	normalized, err := config.NormalizeDomain(filter)
	if err != nil {
		return false
	}
	for _, name := range domain.Names {
		if name == normalized {
			return true
		}
	}
	return false
}

func newRunID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func mustMode(value string, fallback os.FileMode) os.FileMode {
	n, err := parseMode(value)
	if err != nil {
		return fallback
	}
	return n
}

func parseMode(value string) (os.FileMode, error) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "0o")
	if value == "" {
		return 0, fmt.Errorf("empty mode")
	}
	var n uint64
	if _, err := fmt.Sscanf(value, "%o", &n); err != nil {
		return 0, err
	}
	return os.FileMode(n), nil
}

func reloadRunner(logger *slog.Logger) Reloader {
	return reload.NewRunner(logger)
}
