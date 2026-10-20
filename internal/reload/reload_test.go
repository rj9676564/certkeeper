package reload

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

func TestRunSuccess(t *testing.T) {
	runner := Runner{Timeout: time.Second, Logger: slog.Default()}
	if err := runner.Run(context.Background(), []string{"echo ok"}); err != nil {
		t.Fatal(err)
	}
}

func TestRunFailure(t *testing.T) {
	runner := Runner{Timeout: time.Second, Logger: slog.Default()}
	if err := runner.Run(context.Background(), []string{"exit 7"}); err == nil {
		t.Fatal("expected reload failure")
	}
}

func TestRunTimeout(t *testing.T) {
	runner := Runner{Timeout: 10 * time.Millisecond, Logger: slog.Default()}
	if err := runner.Run(context.Background(), []string{"sleep 1"}); err == nil {
		t.Fatal("expected timeout")
	}
}
