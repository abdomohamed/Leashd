package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/abdotalema/leashd/internal/version"
	"github.com/spf13/cobra"
)

var (
	flagLogLevel string
	flagDir      string

	logger *slog.Logger
)

// rootCmd is the top-level cobra command.
var rootCmd = &cobra.Command{
	Use:   "leashd",
	Short: "Per-project eBPF network firewall",
	Long: `leashd enforces per-project trusted domain rules at the kernel level,
detecting and blocking unexpected outbound connections from your processes.`,
	Version:       version.Version,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var level slog.Level
		switch flagLogLevel {
		case "debug":
			level = slog.LevelDebug
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		case "info":
			level = slog.LevelInfo
		default:
			return fmt.Errorf("invalid log level %q (must be debug, info, warn, or error)", flagLogLevel)
		}
		handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
		logger = slog.New(handler)
		slog.SetDefault(logger)
		return nil
	},
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagLogLevel, "log-level", "info",
		"Log level: debug, info, warn, error (env: LEASHD_LOG_LEVEL)")
	rootCmd.PersistentFlags().StringVar(&flagDir, "dir", "",
		"Project directory (default: current working directory)")

	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(auditCmd)
}

// projectDir returns the resolved project directory (--dir flag or cwd).
func projectDir() (string, error) {
	if flagDir != "" {
		return flagDir, nil
	}
	return os.Getwd()
}
