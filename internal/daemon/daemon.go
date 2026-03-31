package daemon

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/abdotalema/leashd/internal/bpf"
	"github.com/abdotalema/leashd/internal/cgroup"
	"github.com/abdotalema/leashd/internal/config"
	ldns "github.com/abdotalema/leashd/internal/dns"
	"github.com/abdotalema/leashd/internal/ipc"
	"github.com/abdotalema/leashd/internal/policy"
	"github.com/fsnotify/fsnotify"
)

// EnrichedEvent is a connect event with reverse DNS and policy verdict resolved.
type EnrichedEvent struct {
	bpf.ConnectEvent
	DstIPStr     string
	ReverseDNS   string
	MatchedRule  string
	FinalVerdict uint8
	Timestamp    time.Time
	PolicyVer    int
	CgroupPath   string
}

// Daemon orchestrates all goroutines for a leashd run session.
type Daemon struct {
	cfg          *config.Config
	cfgPath      string
	projectDir   string
	loader       *bpf.Loader
	resolver     *ldns.Resolver
	engine       *policy.Engine
	dispatcher   *Dispatcher
	cgroupMgr    *cgroup.Manager
	ipcServer    *ipc.Server
	broker       *ipc.Broker
	dnsServerIPs []net.IP

	eventCh  chan bpf.ConnectEvent
	enrichCh chan EnrichedEvent

	policyVer  atomic.Int32
	totalEvts  atomic.Int64
	violations atomic.Int64

	logger *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a Daemon. Call Start() to begin processing.
func New(
	cfgPath string,
	projectDir string,
	loader *bpf.Loader,
	resolver *ldns.Resolver,
	engine *policy.Engine,
	dispatcher *Dispatcher,
	cgroupMgr *cgroup.Manager,
	dnsServerIPs []net.IP,
	logger *slog.Logger,
) (*Daemon, error) {
	ctx, cancel := context.WithCancel(context.Background())

	sockPath, err := ipc.ProjectSocketPath(projectDir)
	if err != nil {
		cancel()
		return nil, err
	}
	srv := ipc.NewServer(sockPath, logger)

	broker := &ipc.Broker{}
	srv.SetBroker(broker)

	d := &Daemon{
		cfgPath:      cfgPath,
		projectDir:   projectDir,
		loader:       loader,
		resolver:     resolver,
		engine:       engine,
		dispatcher:   dispatcher,
		cgroupMgr:    cgroupMgr,
		dnsServerIPs: dnsServerIPs,
		ipcServer:    srv,
		broker:       broker,
		eventCh:    make(chan bpf.ConnectEvent, 4096),
		enrichCh:   make(chan EnrichedEvent, 1024),
		logger:     logger,
		ctx:        ctx,
		cancel:     cancel,
	}
	srv.SetStatusFunc(d.statusSnapshot)
	return d, nil
}

// Start launches all background goroutines.
func (d *Daemon) Start() error {
	// Start IPC socket server.
	if err := d.ipcServer.Start(); err != nil {
		return err
	}

	// Start rules watcher.
	d.wg.Add(1)
	go func() { defer d.wg.Done(); d.runRulesWatcher() }()

	// Start DNS refresh.
	if d.resolver != nil {
		d.wg.Add(1)
		go func() { defer d.wg.Done(); d.runDNSRefresher() }()
	}

	// Start event consumer (reads ring buffer).
	d.wg.Add(1)
	go func() { defer d.wg.Done(); d.runEventConsumer() }()

	// Start policy engine worker.
	d.wg.Add(1)
	go func() { defer d.wg.Done(); d.runPolicyEngine() }()

	// Start alert dispatcher.
	d.wg.Add(1)
	go func() { defer d.wg.Done(); d.runAlertDispatcher() }()

	return nil
}

// Stop cancels all goroutines and waits for them to finish.
func (d *Daemon) Stop() {
	d.cancel()
	d.wg.Wait()
	d.ipcServer.Stop()
}

// statusSnapshot returns a live snapshot for the IPC status command.
func (d *Daemon) statusSnapshot() ipc.StatusResponse {
	cgroupID := uint64(0)
	cgroupPath := ""
	if d.cgroupMgr != nil {
		cgroupPath = d.cgroupMgr.Path()
		if id, err := d.cgroupMgr.CgroupID(); err == nil {
			cgroupID = id
		}
	}
	return ipc.StatusResponse{
		Active:        true,
		PolicyVersion: int(d.policyVer.Load()),
		TotalEvents:   d.totalEvts.Load(),
		Violations:    d.violations.Load(),
		CgroupID:      cgroupID,
		CgroupPath:    cgroupPath,
	}
}

func (d *Daemon) runRulesWatcher() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		d.logger.Error("create rules watcher", "error", err)
		return
	}
	defer func() { _ = watcher.Close() }()
	if err := watcher.Add(d.cfgPath); err != nil {
		d.logger.Error("watch rules file", "path", d.cfgPath, "error", err)
		return
	}
	for {
		select {
		case <-d.ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) ||
				event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) {
				d.logger.Info("rules.yaml change detected", "path", d.cfgPath)
				// Re-add in case the file was atomically replaced (rename-over):
				// inotify fires IN_DELETE_SELF (Remove) on the replaced inode and
				// drops the watch; re-adding here watches the new inode.
				_ = watcher.Add(d.cfgPath)
				d.reloadPolicy()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			d.logger.Error("rules watcher error", "error", err)
		}
	}
}

func (d *Daemon) reloadPolicy() {
	start := time.Now()
	cfg, err := config.Load(d.cfgPath)
	if err != nil {
		d.logger.Error("hot-reload failed: parse error (old policy retained)", "error", err)
		return
	}

	// Collect all non-wildcard domains for resolution.
	var domains []string
	for _, rule := range cfg.Rules {
		domains = append(domains, rule.Domains...)
	}

	resolvedIPs := make(map[string][]net.IP)
	if d.resolver != nil {
		_ = d.resolver.ResolveAll(domains)
		for _, dom := range domains {
			if ips := d.resolver.Lookup(dom); ips != nil {
				resolvedIPs[dom] = ips
			}
		}
	}

	ver := int(d.policyVer.Add(1))
	compiled, err := policy.Compile(cfg, resolvedIPs, d.dnsServerIPs, ver)
	if err != nil {
		d.logger.Error("hot-reload failed: compile error (old policy retained)", "error", err)
		return
	}

	// Push new entries to BPF map.
	if d.loader != nil {
		maps := d.loader.Maps()
		for _, entry := range compiled.Entries {
			if err := maps.SetPolicy(entry.PrefixLen, entry.IP, entry.Verdict); err != nil {
				d.logger.Error("BPF map update failed during reload", "error", err)
			}
		}
	}

	d.engine.UpdatePolicy(cfg, compiled)
	d.logger.Info("hot-reload succeeded",
		"elapsed_ms", time.Since(start).Milliseconds(),
		"rules", len(cfg.Rules),
		"policy_version", ver,
	)
}

func (d *Daemon) runDNSRefresher() {
	var domains []string
	if d.cfg != nil {
		for _, rule := range d.cfg.Rules {
			domains = append(domains, rule.Domains...)
		}
	}
	d.resolver.Start(d.ctx, domains)

	for {
		select {
		case <-d.ctx.Done():
			return
		case update := <-d.resolver.Updates():
			d.logger.Info("DNS IP change — triggering policy recompile",
				"domain", update.Domain,
				"old_ips", update.OldIPs,
				"new_ips", update.NewIPs,
			)
			d.reloadPolicy()
		}
	}
}

func (d *Daemon) runEventConsumer() {
	reader, err := d.loader.NewRingBufReader()
	if err != nil {
		d.logger.Error("create ring buffer reader", "error", err)
		return
	}
	defer func() { _ = reader.Close() }()

	// reader.Read() blocks until an event arrives or the reader is closed.
	// When the context is cancelled we must close the reader to unblock it;
	// otherwise wg.Wait() in Stop() will deadlock.
	go func() {
		<-d.ctx.Done()
		_ = reader.Close()
	}()

	for {
		record, err := reader.Read()
		if err != nil {
			if d.ctx.Err() != nil {
				return
			}
			d.logger.Error("ring buffer read error", "error", err)
			continue
		}

		var evt bpf.ConnectEvent
		if err := parseEvent(record.RawSample, &evt); err != nil {
			d.logger.Warn("failed to parse ring buffer event", "error", err)
			continue
		}

		d.logger.Debug("ring_buf_event",
			"pid", evt.PID,
			"comm", commString(evt.Comm),
			"dst_ip", uint32ToIPStr(evt.DstIP),
			"dst_port", networkToHostPort(evt.DstPort),
			"cgroup_id", evt.CgroupID,
			"kernel_verdict", evt.Verdict,
		)

		select {
		case d.eventCh <- evt:
		default:
			d.logger.Warn("event channel full — event dropped")
		}
	}
}

func (d *Daemon) runPolicyEngine() {
	for {
		select {
		case <-d.ctx.Done():
			return
		case evt := <-d.eventCh:
			d.totalEvts.Add(1)

			dstIP := uint32ToNetIP(evt.DstIP)
			verdict, ruleID, rdns := d.engine.Verdict(dstIP)

			if verdict != policy.VerdictAllow {
				d.violations.Add(1)
			}

			enriched := EnrichedEvent{
				ConnectEvent: evt,
				DstIPStr:     dstIP.String(),
				ReverseDNS:   rdns,
				MatchedRule:  ruleID,
				FinalVerdict: verdict,
				Timestamp:    time.Now(),
				PolicyVer:    int(d.policyVer.Load()),
			}
			if d.cgroupMgr != nil {
				enriched.CgroupPath = d.cgroupMgr.Path()
			}

			// If engine verdict differs from kernel verdict, update BPF map.
			if verdict != evt.Verdict && d.loader != nil {
				_ = d.loader.Maps().SetPolicy(32, evt.DstIP, verdict)
			}

			select {
			case d.enrichCh <- enriched:
			default:
			}
		}
	}
}

func (d *Daemon) runAlertDispatcher() {
	for {
		select {
		case <-d.ctx.Done():
			return
		case evt := <-d.enrichCh:
			d.dispatcher.Dispatch(d.ctx, evt)
			if d.broker != nil {
				if data, err := marshalLogEvent(evt); err == nil {
					d.broker.Publish(data)
				}
			}
		}
	}
}
