package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"

	"github.com/rj9676564/certkeeper/internal/config"
)

type Event string

const (
	EventFailure Event = "failure"
	EventRenewed Event = "renewed"
	EventSkipped Event = "skipped"
)

type Data struct {
	Status      string
	Domain      string
	Error       string
	ExpiresAt   string
	DaysLeft    int
	DNSProvider string
	Hostname    string
	Time        string
	RunID       string
}

type Notifier struct {
	cfg    config.NotifyConfig
	client *http.Client
	logger *slog.Logger
}

func New(cfg config.NotifyConfig, logger *slog.Logger) *Notifier {
	timeout, err := time.ParseDuration(cfg.Timeout)
	if err != nil {
		timeout = 10 * time.Second
	}
	return &Notifier{
		cfg:    cfg,
		client: &http.Client{Timeout: timeout},
		logger: logger,
	}
}

func (n *Notifier) Notify(ctx context.Context, event Event, data Data) {
	if n == nil {
		return
	}
	if data.Time == "" {
		data.Time = time.Now().UTC().Format(time.RFC3339)
	}
	if data.Hostname == "" {
		data.Hostname, _ = os.Hostname()
	}
	for _, hook := range n.cfg.Webhooks {
		if !eventMatches(hook.Events, event) {
			continue
		}
		if err := n.sendWebhook(ctx, hook, data); err != nil {
			n.logger.Error("webhook failed", "name", hook.Name, "event", string(event), "error", err)
		}
	}
	if event == EventFailure && strings.TrimSpace(n.cfg.FailureCommand) != "" {
		if err := n.runFailureCommand(ctx, data); err != nil {
			n.logger.Error("failure_command failed", "error", err)
		}
	}
}

func (n *Notifier) sendWebhook(ctx context.Context, hook config.Webhook, data Data) error {
	body, err := renderBody(hook.Body, data)
	if err != nil {
		return fmt.Errorf("render body: %w", err)
	}
	attempts := n.cfg.Retries + 1
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := n.doRequest(ctx, hook, body); err != nil {
			lastErr = err
			if attempt < attempts {
				delay := time.Duration(attempt) * time.Second
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(delay):
				}
			}
			continue
		}
		return nil
	}
	return lastErr
}

func (n *Notifier) doRequest(ctx context.Context, hook config.Webhook, body []byte) error {
	method := strings.ToUpper(hook.Method)
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, hook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for key, value := range hook.Headers {
		req.Header.Set(key, value)
	}
	if req.Header.Get("Content-Type") == "" && len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (n *Notifier) runFailureCommand(parent context.Context, data Data) error {
	timeout, err := time.ParseDuration(n.cfg.Timeout)
	if err != nil {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", n.cfg.FailureCommand)
	cmd.Env = append(os.Environ(),
		"CERTKEEPER_STATUS="+data.Status,
		"CERTKEEPER_DOMAIN="+data.Domain,
		"CERTKEEPER_ERROR="+data.Error,
		"CERTKEEPER_EXPIRES_AT="+data.ExpiresAt,
		fmt.Sprintf("CERTKEEPER_DAYS_LEFT=%d", data.DaysLeft),
		"CERTKEEPER_DNS_PROVIDER="+data.DNSProvider,
		"CERTKEEPER_RUN_ID="+data.RunID,
		"CERTKEEPER_TIME="+data.Time,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func renderBody(body string, data Data) ([]byte, error) {
	if strings.TrimSpace(body) == "" {
		payload := map[string]any{
			"service":      "certkeeper",
			"status":       data.Status,
			"domain":       data.Domain,
			"error":        data.Error,
			"expires_at":   data.ExpiresAt,
			"days_left":    data.DaysLeft,
			"dns_provider": data.DNSProvider,
			"hostname":     data.Hostname,
			"time":         data.Time,
			"run_id":       data.RunID,
		}
		return json.Marshal(payload)
	}
	tmpl, err := template.New("webhook").Parse(body)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func eventMatches(events []string, event Event) bool {
	for _, item := range events {
		if item == string(event) {
			return true
		}
	}
	return false
}
