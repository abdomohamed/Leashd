package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/abdotalema/leashd/internal/config"
	"github.com/abdotalema/leashd/internal/policy"
	"github.com/fatih/color"
)

// Sink is implemented by each output destination.
type Sink interface {
	Write(ctx context.Context, event EnrichedEvent) error
	Close() error
}

// Dispatcher fans out enriched events to all configured sinks.
type Dispatcher struct {
	sinks  []Sink
	logger *slog.Logger
}

// NewDispatcher creates a Dispatcher from the notifications config.
func NewDispatcher(notif config.Notifications, projectDir string, logger *slog.Logger) (*Dispatcher, error) {
	var sinks []Sink

	if notif.Terminal {
		sinks = append(sinks, &TerminalSink{logger: logger})
	}

	logPath := notif.JSONLog
	if logPath == "" {
		logPath = config.DefaultLogPath(projectDir)
	}
	if err := os.MkdirAll(dirOf(logPath), 0700); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open event log %s: %w", logPath, err)
	}
	sinks = append(sinks, &JSONLogSink{file: f, enc: json.NewEncoder(f)})

	if notif.Webhook != nil && notif.Webhook.URL != "" {
		onSet := make(map[string]bool)
		for _, v := range notif.Webhook.On {
			onSet[v] = true
		}
		sinks = append(sinks, &WebhookSink{
			client: &http.Client{Timeout: 5 * time.Second},
			url:    notif.Webhook.URL,
			on:     onSet,
			logger: logger,
		})
	}

	return &Dispatcher{sinks: sinks, logger: logger}, nil
}

// Dispatch sends evt to all sinks.
func (d *Dispatcher) Dispatch(ctx context.Context, evt EnrichedEvent) {
	d.logger.Info("event dispatched",
		"pid", evt.PID,
		"comm", commString(evt.Comm),
		"dst_ip", evt.DstIPStr,
		"dst_port", networkToHostPort(evt.DstPort),
		"verdict", verdictName(evt.FinalVerdict),
		"matched_rule", evt.MatchedRule,
	)
	for _, sink := range d.sinks {
		if err := sink.Write(ctx, evt); err != nil {
			d.logger.Error("sink write error", "error", err)
		}
	}
}

// Close flushes and closes all sinks.
func (d *Dispatcher) Close() {
	for _, sink := range d.sinks {
		_ = sink.Close()
	}
}

// TerminalSink prints colored violation lines to stderr.
type TerminalSink struct {
	logger *slog.Logger
}

func (t *TerminalSink) Write(_ context.Context, evt EnrichedEvent) error {
	if evt.FinalVerdict == policy.VerdictAllow {
		return nil
	}
	tag := color.YellowString("[WARN]")
	if evt.FinalVerdict == policy.VerdictBlock {
		tag = color.RedString("[BLOCK]")
	}
	rdns := evt.ReverseDNS
	if rdns == "" {
		rdns = "unknown"
	}
	fmt.Fprintf(os.Stderr, "%s %s (pid %d) → %s (%s:%d)\n",
		tag,
		commString(evt.Comm),
		evt.PID,
		evt.DstIPStr,
		rdns,
		networkToHostPort(evt.DstPort),
	)
	return nil
}
func (t *TerminalSink) Close() error { return nil }

// JSONLogSink appends JSON-encoded events to a file.
type JSONLogSink struct {
	file *os.File
	enc  *json.Encoder
	mu   sync.Mutex
}

// logEvent is the JSON representation written to the event log.
type logEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	PID        uint32    `json:"pid"`
	Comm       string    `json:"comm"`
	DstIP      string    `json:"dst_ip"`
	DstPort    uint16    `json:"dst_port"`
	Protocol   uint8     `json:"protocol"`
	ReverseDNS string    `json:"reverse_dns,omitempty"`
	MatchedRule string   `json:"matched_rule,omitempty"`
	Verdict    string    `json:"verdict"`
	Meta       logMeta   `json:"_meta"`
}

type logMeta struct {
	CgroupID      uint64 `json:"cgroup_id"`
	CgroupPath    string `json:"cgroup_path"`
	KernelVerdict string `json:"kernel_verdict"`
	EngineOverride bool  `json:"engine_override"`
	PolicyVersion int    `json:"policy_version"`
}

func (j *JSONLogSink) Write(_ context.Context, evt EnrichedEvent) error {
	entry := logEvent{
		Timestamp:   evt.Timestamp,
		PID:         evt.PID,
		Comm:        commString(evt.Comm),
		DstIP:       evt.DstIPStr,
		DstPort:     networkToHostPort(evt.DstPort),
		Protocol:    evt.Protocol,
		ReverseDNS:  evt.ReverseDNS,
		MatchedRule: evt.MatchedRule,
		Verdict:     verdictName(evt.FinalVerdict),
		Meta: logMeta{
			CgroupID:       evt.CgroupID,
			CgroupPath:     evt.CgroupPath,
			KernelVerdict:  verdictName(evt.Verdict),
			EngineOverride: evt.Verdict != evt.FinalVerdict,
			PolicyVersion:  evt.PolicyVer,
		},
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.enc.Encode(entry)
}
func (j *JSONLogSink) Close() error { return j.file.Close() }

// WebhookSink POSTs events to a webhook URL.
type WebhookSink struct {
	client *http.Client
	url    string
	on     map[string]bool
	logger *slog.Logger
}

func (w *WebhookSink) Write(ctx context.Context, evt EnrichedEvent) error {
	name := verdictName(evt.FinalVerdict)
	if !w.on[name] {
		return nil
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		w.logger.Warn("webhook delivery failed", "url", w.url, "error", err)
		return nil // non-fatal
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		w.logger.Warn("webhook returned error", "url", w.url, "status", resp.StatusCode)
	}
	return nil
}
func (w *WebhookSink) Close() error { return nil }

func verdictName(v uint8) string {
	switch v {
	case 0:
		return "allow"
	case 1:
		return "warn"
	case 2:
		return "block"
	default:
		return fmt.Sprintf("unknown(%d)", v)
	}
}

// marshalLogEvent encodes evt in the same JSON format as JSONLogSink.
func marshalLogEvent(evt EnrichedEvent) ([]byte, error) {
	return json.Marshal(logEvent{
		Timestamp:   evt.Timestamp,
		PID:         evt.PID,
		Comm:        commString(evt.Comm),
		DstIP:       evt.DstIPStr,
		DstPort:     networkToHostPort(evt.DstPort),
		Protocol:    evt.Protocol,
		ReverseDNS:  evt.ReverseDNS,
		MatchedRule: evt.MatchedRule,
		Verdict:     verdictName(evt.FinalVerdict),
		Meta: logMeta{
			CgroupID:       evt.CgroupID,
			CgroupPath:     evt.CgroupPath,
			KernelVerdict:  verdictName(evt.Verdict),
			EngineOverride: evt.Verdict != evt.FinalVerdict,
			PolicyVersion:  evt.PolicyVer,
		},
	})
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
