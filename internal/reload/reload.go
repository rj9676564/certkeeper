package reload

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Runner struct {
	Timeout time.Duration
	Logger  *slog.Logger
}

func (r Runner) Run(ctx context.Context, commands []string) error {
	if len(commands) == 0 {
		return nil
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	var errs []error
	for _, command := range commands {
		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}
		if r.Logger != nil {
			r.Logger.Info("running reload command", "command", command)
		}
		cmdCtx, cancel := context.WithTimeout(ctx, timeout)
		cmd := exec.CommandContext(cmdCtx, "/bin/sh", "-c", command)
		cmd.Env = os.Environ()
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("reload command %q: %w: %s", command, err, strings.TrimSpace(string(out))))
			continue
		}
		if r.Logger != nil && strings.TrimSpace(string(out)) != "" {
			r.Logger.Info("reload command output", "command", command, "output", strings.TrimSpace(string(out)))
		}
	}
	return errors.Join(errs...)
}

func NewRunner(logger *slog.Logger) Runner {
	return Runner{Logger: logger}
}
