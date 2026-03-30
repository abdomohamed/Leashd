package ipc

// Request is the JSON message sent by a client to the server.
type Request struct {
	Cmd string `json:"cmd"`
}

// Response is the JSON message returned for a "status" command.
type StatusResponse struct {
	Active        bool    `json:"active"`
	PolicyVersion int     `json:"policy_version"`
	EventsPerSec  float64 `json:"events_per_sec"`
	TotalEvents   int64   `json:"total_events"`
	Violations    int64   `json:"violations"`
	CgroupID      uint64  `json:"cgroup_id"`
	CgroupPath    string  `json:"cgroup_path"`
}

// ErrorResponse is returned when a command fails.
type ErrorResponse struct {
	Error string `json:"error"`
}

// Commands understood by the IPC server.
const (
	CmdStatus = "status" // one-shot: return StatusResponse
	CmdStream = "stream" // streaming: emit EnrichedEvent JSON lines until client disconnects
)
