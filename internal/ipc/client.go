package ipc

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Client connects to a running leashd session's IPC socket.
type Client struct {
	socketPath string
}

// NewClient creates a Client targeting the socket for the given project directory.
func NewClient(projectDir string) (*Client, error) {
	path, err := ProjectSocketPath(projectDir)
	if err != nil {
		return nil, err
	}
	return &Client{socketPath: path}, nil
}

// Status queries the running daemon and returns its current status.
// Returns a descriptive error if no session is running.
func (c *Client) Status() (*StatusResponse, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	enc := json.NewEncoder(conn)
	if err := enc.Encode(Request{Cmd: CmdStatus}); err != nil {
		return nil, fmt.Errorf("send status request: %w", err)
	}

	var resp StatusResponse
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode status response: %w", err)
	}
	return &resp, nil
}

func (c *Client) dial() (*net.UnixConn, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, 3*time.Second)
	if err != nil {
		return nil, &NoSessionError{Path: c.socketPath}
	}
	return conn.(*net.UnixConn), nil
}

// NoSessionError is returned when no leashd session is found.
type NoSessionError struct {
	Path string
}

func (e *NoSessionError) Error() string {
	return fmt.Sprintf("no leashd session running in this directory (expected socket: %s)", e.Path)
}
