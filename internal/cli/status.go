package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/abdotalema/leashd/internal/ipc"
	"github.com/spf13/cobra"
)

var flagStatusJSON bool

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current leashd session status",
	Long: `leashd status queries the running leashd session in the current
project directory and displays live connection statistics.`,
	RunE: runStatus,
}

func init() {
	statusCmd.Flags().BoolVar(&flagStatusJSON, "json", false, "Output as JSON")
}

func runStatus(cmd *cobra.Command, args []string) error {
	dir, err := projectDir()
	if err != nil {
		return err
	}

	client, err := ipc.NewClient(dir)
	if err != nil {
		return err
	}

	resp, err := client.Status()
	if err != nil {
		// Check if it's a "no session" error.
		if _, ok := err.(*ipc.NoSessionError); ok {
			fmt.Fprintln(os.Stderr, "No leashd session running in this directory.")
			fmt.Fprintln(os.Stderr, "Start one with: sudo leashd run <command>")
			os.Exit(1)
		}
		return err
	}

	if flagStatusJSON {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	fmt.Printf("Status:         active\n")
	fmt.Printf("Cgroup:         %s (id=%d)\n", resp.CgroupPath, resp.CgroupID)
	fmt.Printf("Policy version: %d\n", resp.PolicyVersion)
	fmt.Printf("Total events:   %d\n", resp.TotalEvents)
	fmt.Printf("Violations:     %d\n", resp.Violations)
	fmt.Printf("Events/sec:     %.1f\n", resp.EventsPerSec)
	return nil
}
