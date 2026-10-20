package notify

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rj9676564/certkeeper/internal/config"
)

func testConfig(urls ...string) config.NotifyConfig {
	hooks := make([]config.Webhook, 0, len(urls))
	for _, u := range urls {
		hooks = append(hooks, config.Webhook{
			Name:   "test",
			URL:    u,
			Method: "POST",
			Events: []string{"failure", "renewed"},
			Body:   `{"domain":"{{.Domain}}","status":"{{.Status}}"}`,
		})
	}
	return config.NotifyConfig{Timeout: "2s", Retries: 1, Webhooks: hooks}
}

func TestWebhook(t *testing.T) {
	var requests atomic.Int32
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		data, _ := io.ReadAll(r.Body)
		body = string(data)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := New(testConfig(server.URL), slog.Default())
	n.Notify(context.Background(), EventFailure, Data{Domain: "example.com", Status: "failed", Error: "boom"})
	if requests.Load() != 1 {
		t.Fatalf("requests = %d", requests.Load())
	}
	if !strings.Contains(body, `"domain":"example.com"`) {
		t.Fatalf("unexpected body: %s", body)
	}
	if !strings.Contains(body, `"status":"failed"`) {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestEventFiltering(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.Webhooks[0].Events = []string{"failure"}
	n := New(cfg, slog.Default())
	n.Notify(context.Background(), EventRenewed, Data{Domain: "example.com"})
	if requests.Load() != 0 {
		t.Fatalf("expected no request, got %d", requests.Load())
	}
	n.Notify(context.Background(), EventFailure, Data{Domain: "example.com"})
	if requests.Load() != 1 {
		t.Fatalf("expected one request, got %d", requests.Load())
	}
}

func TestRetry(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.Retries = 2
	n := New(cfg, slog.Default())
	n.Notify(context.Background(), EventFailure, Data{Domain: "example.com"})
	if requests.Load() != 2 {
		t.Fatalf("requests = %d", requests.Load())
	}
}

func TestFailureCommand(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "notification.txt")
	cfg := config.NotifyConfig{
		Timeout:        "2s",
		Retries:        1,
		FailureCommand: `printf '%s' "$CERTKEEPER_DOMAIN" > ` + out,
	}
	n := New(cfg, slog.Default())
	n.Notify(context.Background(), EventFailure, Data{Domain: "example.com", Status: "failed"})
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "example.com" {
		t.Fatalf("unexpected output: %s", data)
	}
}

func TestDefaultBody(t *testing.T) {
	body, err := renderBody("", Data{Domain: "example.com", Status: "failed", DaysLeft: -1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"domain":"example.com"`) {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestTimeoutConfigured(t *testing.T) {
	n := New(config.NotifyConfig{Timeout: "1ms"}, slog.Default())
	if n.client.Timeout != time.Millisecond {
		t.Fatalf("timeout = %s", n.client.Timeout)
	}
}
