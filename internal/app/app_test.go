package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rj9676564/certkeeper/internal/acme"
	"github.com/rj9676564/certkeeper/internal/config"
	"github.com/rj9676564/certkeeper/internal/notify"
)

type fakeIssuer struct {
	calls    int
	last     acme.IssueRequest
	notAfter time.Time
	err      error
}

func (f *fakeIssuer) Issue(ctx context.Context, req acme.IssueRequest) (*acme.Result, error) {
	f.calls++
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	notAfter := f.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	certPEM, keyPEM, err := makeTestCert(req.Domains, notAfter)
	if err != nil {
		return nil, err
	}
	return &acme.Result{CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}, nil
}

type fakeNotifier struct {
	events []notify.Event
	data   []notify.Data
}

func (f *fakeNotifier) Notify(ctx context.Context, event notify.Event, data notify.Data) {
	f.events = append(f.events, event)
	f.data = append(f.data, data)
}

type fakeReloader struct {
	commands []string
	err      error
}

func (f *fakeReloader) Run(ctx context.Context, commands []string) error {
	f.commands = append(f.commands, commands...)
	return f.err
}

func makeTestConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	backup := true
	return &config.Config{
		Version:         1,
		Email:           "test@example.com",
		RenewBeforeDays: 30,
		Storage: config.StorageConfig{
			Dir:      filepath.Join(dir, "certs"),
			StateDir: filepath.Join(dir, "data"),
			CertMode: "0644",
			KeyMode:  "0600",
			Backup:   &backup,
		},
		DNSProviders: map[string]config.DNSProvider{
			"main": {
				Type:               "alidns",
				AccessKey:          "ak",
				SecretKey:          "sk",
				RegionID:           "cn-hangzhou",
				TTL:                600,
				PropagationTimeout: "60s",
				PollingInterval:    "2s",
				HTTPTimeout:        "10s",
			},
		},
		Domains: []config.Domain{{Name: "example.com", DNS: "main", Reload: []string{"reload-cmd"}}},
		Notify:  config.NotifyConfig{Timeout: "1s", Retries: 1},
	}
}

func makeTestCert(names []string, notAfter time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

func TestRunRenewsThenSkips(t *testing.T) {
	cfg := makeTestConfig(t)
	now := time.Now().Truncate(time.Second)
	issuer := &fakeIssuer{notAfter: now.Add(90 * 24 * time.Hour)}
	notifier := &fakeNotifier{}
	reloader := &fakeReloader{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	summary, err := Run(context.Background(), Options{
		Config: cfg, Logger: logger, Issuer: issuer, Notifier: notifier, Reloader: reloader,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Renewed != 1 || summary.Failed != 0 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if issuer.calls != 1 {
		t.Fatalf("issuer calls = %d", issuer.calls)
	}
	if len(reloader.commands) != 1 || reloader.commands[0] != "reload-cmd" {
		t.Fatalf("reload commands: %#v", reloader.commands)
	}
	if len(notifier.events) != 1 || notifier.events[0] != notify.EventRenewed {
		t.Fatalf("notifier events: %#v", notifier.events)
	}
	domains, err := cfg.ResolveDomains()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(domains[0].CertPath); err != nil {
		t.Fatal(err)
	}

	summary, err = Run(context.Background(), Options{
		Config: cfg, Logger: logger, Issuer: issuer, Notifier: notifier, Reloader: reloader,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Skipped != 1 || issuer.calls != 1 {
		t.Fatalf("expected skip, summary=%+v calls=%d", summary, issuer.calls)
	}
}

func TestRunForceAndDryRun(t *testing.T) {
	cfg := makeTestConfig(t)
	now := time.Now().Truncate(time.Second)
	issuer := &fakeIssuer{notAfter: now.Add(90 * 24 * time.Hour)}
	notifier := &fakeNotifier{}
	reloader := &fakeReloader{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	opts := Options{Config: cfg, Logger: logger, Issuer: issuer, Notifier: notifier, Reloader: reloader, Now: func() time.Time { return now }}
	if _, err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	opts.Force = true
	summary, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Renewed != 1 || issuer.calls != 2 {
		t.Fatalf("force did not renew: %+v calls=%d", summary, issuer.calls)
	}
	opts.Force = false
	opts.DryRun = true
	summary, err = Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Results[0].Action != "skipped" {
		// 90 days left, not due; dry run only reports would-renew when due.
		t.Fatalf("unexpected dry-run action: %s", summary.Results[0].Action)
	}
}

func TestRunIssuerFailureNotifies(t *testing.T) {
	cfg := makeTestConfig(t)
	issuer := &fakeIssuer{err: errors.New("acme exploded")}
	notifier := &fakeNotifier{}
	reloader := &fakeReloader{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	summary, err := Run(context.Background(), Options{
		Config: cfg, Logger: logger, Issuer: issuer, Notifier: notifier, Reloader: reloader,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if summary.Failed != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if len(notifier.events) != 1 || notifier.events[0] != notify.EventFailure {
		t.Fatalf("notifier events: %#v", notifier.events)
	}
}

func TestRunReloadFailure(t *testing.T) {
	cfg := makeTestConfig(t)
	issuer := &fakeIssuer{}
	notifier := &fakeNotifier{}
	reloader := &fakeReloader{err: errors.New("reload failed")}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	summary, err := Run(context.Background(), Options{
		Config: cfg, Logger: logger, Issuer: issuer, Notifier: notifier, Reloader: reloader,
	})
	if err == nil {
		t.Fatal("expected reload error")
	}
	if summary.Failed != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if notifier.events[0] != notify.EventFailure {
		t.Fatalf("notifier events: %#v", notifier.events)
	}
}

func TestCheck(t *testing.T) {
	cfg := makeTestConfig(t)
	now := time.Now().Truncate(time.Second)
	issuer := &fakeIssuer{notAfter: now.Add(90 * 24 * time.Hour)}
	notifier := &fakeNotifier{}
	reloader := &fakeReloader{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	if _, err := Run(context.Background(), Options{Config: cfg, Logger: logger, Issuer: issuer, Notifier: notifier, Reloader: reloader, Now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	summary, err := Check(context.Background(), cfg, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Results[0].Action != "ok" {
		t.Fatalf("unexpected check result: %+v", summary.Results[0])
	}
}
