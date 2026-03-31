package cli

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/abdotalema/leashd/internal/bpf"
	"github.com/abdotalema/leashd/internal/cgroup"
	"github.com/abdotalema/leashd/internal/config"
	"github.com/abdotalema/leashd/internal/daemon"
	ldns "github.com/abdotalema/leashd/internal/dns"
	"github.com/abdotalema/leashd/internal/policy"
	"github.com/abdotalema/leashd/internal/privdrop"
	"github.com/spf13/cobra"
)

var (
	flagRunCgroupName  string
	flagRunNoDaemon    bool
	flagRunUser        string
	flagRunNoDropPrivs bool
)

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <command> [args...]",
	Short: "Run a command under leashd network enforcement",
	Long: `leashd run wraps a command inside a dedicated Linux cgroup and
enforces per-project network rules from rules.yaml using eBPF.

Requires: root or CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN.`,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runRun,
}

func init() {
	runCmd.Flags().StringVar(&flagRunCgroupName, "cgroup-name", "", "Override cgroup name (default: leashd-<pid>)")
	runCmd.Flags().BoolVar(&flagRunNoDaemon, "no-daemon", false, "Dry-run: start child without eBPF enforcement")
	runCmd.Flags().StringVar(&flagRunUser, "user", "", "Drop to this user before running the command (default: auto-detect from SUDO_UID)")
	runCmd.Flags().BoolVar(&flagRunNoDropPrivs, "no-drop-privs", false, "Keep child running as root (not recommended)")
}

func runRun(cmd *cobra.Command, args []string) error {
	dir, err := projectDir()
	if err != nil {
		return err
	}

	// Preflight checks.
	if err := preflight(); err != nil {
		return err
	}

	// Load rules.yaml.
	rulesPath := filepath.Join(dir, "rules.yaml")
	cfg, err := config.Load(rulesPath)
	if err != nil {
		return fmt.Errorf("load rules.yaml: %w", err)
	}
	logger.Info("rules.yaml loaded", "path", rulesPath, "rules", len(cfg.Rules))

	// Create cgroup.
	cgroupName := flagRunCgroupName
	if cgroupName == "" {
		cgroupName = fmt.Sprintf("leashd-%d", os.Getpid())
	}
	mgr := cgroup.NewManager(cgroupName)
	if err := mgr.Create(); err != nil {
		return fmt.Errorf("create cgroup: %w", err)
	}
	defer func() {
		if err := mgr.Delete(); err != nil {
			logger.Warn("failed to delete cgroup on exit", "error", err)
		}
	}()

	cgroupID, err := mgr.CgroupID()
	if err != nil {
		return fmt.Errorf("get cgroup ID: %w", err)
	}
	logger.Info("cgroup created", "path", mgr.Path(), "cgroup_id", cgroupID)

	var (
		loader     *bpf.Loader
		dmn        *daemon.Daemon
	)

	if !flagRunNoDaemon {
		// Load and attach eBPF programs.
		loader, err = bpf.Load(logger)
		if err != nil {
			return fmt.Errorf("load eBPF: %w", err)
		}
		defer loader.Close()

		if err := loader.AttachKprobes(); err != nil {
			return fmt.Errorf("attach kprobes: %w", err)
		}

		cgroupLink, err := loader.AttachCgroup(mgr.Path())
		if err != nil {
			return fmt.Errorf("attach cgroup/skb: %w", err)
		}
		defer func() { _ = cgroupLink.Close() }()

		maps := loader.Maps()
		if err := maps.AddTrackedCgroup(cgroupID); err != nil {
			return fmt.Errorf("register cgroup in BPF map: %w", err)
		}
		defer func() { _ = maps.RemoveTrackedCgroup(cgroupID) }()

		// Build DNS resolver + policy engine.
		resolver := ldns.NewResolver(logger, nil)

		// Discover system nameservers so DNS resolution is always permitted,
		// even when defaults.action is "block".
		dnsServerIPs := ldns.SystemNameservers()
		if len(dnsServerIPs) > 0 {
			logger.Info("auto-allowing system DNS nameservers", "nameservers", formatIPs(dnsServerIPs))
		} else {
			logger.Warn("no system DNS nameservers found in /etc/resolv.conf")
		}

		var domains []string
		resolvedIPs := make(map[string][]net.IP)
		for _, rule := range cfg.Rules {
			for _, dom := range rule.Domains {
				if !strings.Contains(dom, "*") {
					domains = append(domains, dom)
				}
			}
		}
		if err := resolver.ResolveAll(domains); err != nil {
			logger.Warn("DNS pre-resolution had errors", "error", err)
		}
		for _, dom := range domains {
			if ips := resolver.Lookup(dom); ips != nil {
				resolvedIPs[dom] = ips
			}
		}

		compiled, err := policy.Compile(cfg, resolvedIPs, dnsServerIPs, 1)
		if err != nil {
			return fmt.Errorf("compile policy: %w", err)
		}
		for _, entry := range compiled.Entries {
			if err := maps.SetPolicy(entry.PrefixLen, entry.IP, entry.Verdict); err != nil {
				logger.Warn("BPF map insert failed", "error", err)
			}
		}

		engine := policy.NewEngine(cfg, compiled, resolver, logger)
		disp, err := daemon.NewDispatcher(cfg.Notifications, dir, logger)
		if err != nil {
			return fmt.Errorf("create dispatcher: %w", err)
		}
		defer disp.Close()

		dmn, err = daemon.New(rulesPath, dir, loader, resolver, engine, disp, mgr, dnsServerIPs, logger)
		if err != nil {
			return fmt.Errorf("create daemon: %w", err)
		}
		if err := dmn.Start(); err != nil {
			return fmt.Errorf("start daemon: %w", err)
		}
		defer dmn.Stop()
	}

	// Resolve privilege-drop credentials for the child process.
	var dropResult *privdrop.Result
	if !flagRunNoDropPrivs {
		dropResult, err = privdrop.Resolve(flagRunUser)
		if err != nil {
			return fmt.Errorf("resolve user for privilege drop: %w", err)
		}
		if dropResult != nil {
			logger.Info("child will drop privileges", "uid", dropResult.UID, "gid", dropResult.GID, "user", dropResult.Username)
		} else {
			logger.Warn("no privilege drop: could not detect invoking user (use --user to specify)")
		}
	}

	// Fork the child into the cgroup.
	child := exec.Command(args[0], args[1:]...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr

	if dropResult != nil {
		child.Env = dropResult.Env(os.Environ())
	}

	cgroupFD, err := mgr.FD()
	if err != nil {
		return fmt.Errorf("open cgroup fd: %w", err)
	}
	child.SysProcAttr = &syscall.SysProcAttr{
		CgroupFD:    int(cgroupFD.Fd()),
		UseCgroupFD: true,
	}
	if dropResult != nil {
		child.SysProcAttr.Credential = dropResult.Credential
	}

	if err := child.Start(); err != nil {
		_ = cgroupFD.Close()
		// Fallback: start without CgroupFD, place into cgroup after.
		child.SysProcAttr = &syscall.SysProcAttr{}
		if dropResult != nil {
			child.SysProcAttr.Credential = dropResult.Credential
		}
		if err2 := child.Start(); err2 != nil {
			return fmt.Errorf("start child process: %w", err2)
		}
	} else {
		_ = cgroupFD.Close()
	}

	// Always write PID to cgroup.procs: CLONE_INTO_CGROUP may silently
	// fail on some kernels (e.g. WSL2), leaving the child in the root cgroup.
	if err := mgr.AddPID(child.Process.Pid); err != nil {
		logger.Warn("failed to add child to cgroup (may already be placed)", "error", err)
	}

	logger.Info("child process started", "pid", child.Process.Pid, "cmd", args[0])

	// Forward signals to child.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for sig := range sigCh {
			_ = child.Process.Signal(sig)
		}
	}()

	err = child.Wait()
	signal.Stop(sigCh)
	close(sigCh)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}

func preflight() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("leashd run requires root (or CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN)")
	}
	if err := cgroup.CheckCgroupV2(); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	return nil
}

func formatIPs(ips []net.IP) []string {
	ss := make([]string, len(ips))
	for i, ip := range ips {
		ss[i] = ip.String()
	}
	return ss
}
