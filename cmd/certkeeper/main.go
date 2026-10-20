package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/rj9676564/certkeeper/internal/app"
	"github.com/rj9676564/certkeeper/internal/config"
	"github.com/rj9676564/certkeeper/internal/version"
	"github.com/spf13/cobra"
)

const defaultConfigPath = "/config/config.yaml"

func main() {
	root := newRootCommand()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var (
		configPath string
		logLevel   string
		logJSON    bool
	)
	root := &cobra.Command{
		Use:           "certkeeper",
		Short:         "Automatic ACME certificate manager for Alibaba Cloud DNS",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			level := slog.LevelInfo
			switch strings.ToLower(logLevel) {
			case "debug":
				level = slog.LevelDebug
			case "warn", "warning":
				level = slog.LevelWarn
			case "error":
				level = slog.LevelError
			case "info", "":
			default:
				return fmt.Errorf("invalid log level %q", logLevel)
			}
			handlerOpts := &slog.HandlerOptions{Level: level}
			var handler slog.Handler
			if logJSON {
				handler = slog.NewJSONHandler(os.Stderr, handlerOpts)
			} else {
				handler = slog.NewTextHandler(os.Stderr, handlerOpts)
			}
			slog.SetDefault(slog.New(handler))
			return nil
		},
	}
	root.PersistentFlags().StringVar(&configPath, "config", "", "path to config.yaml")
	root.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")
	root.PersistentFlags().BoolVar(&logJSON, "log-json", false, "emit JSON logs")

	root.AddCommand(newRunCommand(&configPath))
	root.AddCommand(newDaemonCommand(&configPath))
	root.AddCommand(newCheckCommand(&configPath))
	root.AddCommand(newVersionCommand())
	return root
}

func newRunCommand(configPath *string) *cobra.Command {
	var (
		dryRun  bool
		staging bool
		force   bool
		domain  string
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Check and renew certificates once",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			summary, runErr := app.Run(cmd.Context(), app.Options{
				Config:  cfg,
				Staging: staging,
				DryRun:  dryRun,
				Force:   force,
				Domain:  domain,
				Logger:  slog.Default(),
			})
			if summary != nil {
				printSummary(summary, jsonOut)
			}
			return runErr
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "check what would be renewed without issuing certificates")
	cmd.Flags().BoolVar(&staging, "staging", false, "use the ACME staging directory")
	cmd.Flags().BoolVar(&force, "force", false, "renew even if the certificate is still valid")
	cmd.Flags().StringVar(&domain, "domain", "", "only process this domain")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print a JSON summary")
	return cmd
}

func newDaemonCommand(configPath *string) *cobra.Command {
	var (
		interval time.Duration
		jitter   float64
		staging  bool
		force    bool
	)
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run forever and renew certificates on a schedule",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			if interval <= 0 {
				return fmt.Errorf("interval must be greater than zero")
			}
			if jitter < 0 || jitter > 1 {
				return fmt.Errorf("jitter must be between 0 and 1")
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			for {
				summary, runErr := app.Run(ctx, app.Options{
					Config:  cfg,
					Staging: staging,
					Force:   force,
					Logger:  slog.Default(),
				})
				if summary != nil {
					printSummary(summary, false)
				}
				if runErr != nil {
					slog.Error("renewal run failed", "error", runErr)
				}
				delay := jittered(interval, jitter)
				slog.Info("sleeping", "duration", delay.String())
				select {
				case <-ctx.Done():
					slog.Info("shutting down")
					return nil
				case <-time.After(delay):
				}
			}
		},
	}
	cmd.Flags().DurationVar(&interval, "interval", 12*time.Hour, "time between renewal checks")
	cmd.Flags().Float64Var(&jitter, "jitter", 0.1, "random jitter fraction applied to the interval (0-1)")
	cmd.Flags().BoolVar(&staging, "staging", false, "use the ACME staging directory")
	cmd.Flags().BoolVar(&force, "force", false, "renew even if the certificate is still valid")
	return cmd
}

func newCheckCommand(configPath *string) *cobra.Command {
	var (
		domain  string
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Print certificate status without renewing",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			summary, checkErr := app.Check(cmd.Context(), cfg, domain, time.Now())
			if summary != nil {
				printSummary(summary, jsonOut)
			}
			return checkErr
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "only check this domain")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print a JSON summary")
	return cmd
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("certkeeper %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
		},
	}
}

func loadConfig(path string) (*config.Config, error) {
	if path == "" {
		path = os.Getenv("CERTKEEPER_CONFIG")
	}
	if path == "" {
		if _, err := os.Stat(defaultConfigPath); err == nil {
			path = defaultConfigPath
		} else {
			path = "config.yaml"
		}
	}
	return config.Load(path)
}

func printSummary(summary *app.Summary, jsonOut bool) {
	if jsonOut {
		data, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			slog.Error("encode summary", "error", err)
			return
		}
		fmt.Println(string(data))
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tACTION\tDAYS LEFT\tEXPIRES\tREASON/ERROR")
	for _, result := range summary.Results {
		expires := ""
		if !result.ExpiresAt.IsZero() {
			expires = result.ExpiresAt.Format("2006-01-02")
		}
		note := result.Reason
		if result.Error != "" {
			note = result.Error
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", result.Domain, result.Action, result.DaysLeft, expires, note)
	}
	_ = w.Flush()
	fmt.Printf("run %s: renewed=%d skipped=%d failed=%d\n", summary.RunID, summary.Renewed, summary.Skipped, summary.Failed)
}

func jittered(interval time.Duration, fraction float64) time.Duration {
	if fraction <= 0 {
		return interval
	}
	delta := float64(interval) * fraction
	offset := (rand.Float64()*2 - 1) * delta
	return interval + time.Duration(offset)
}
