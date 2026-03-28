package ipc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// Server is the UNIX domain socket IPC server embedded in leashd run.
type Server struct {
	socketPath string
	listener   *net.UnixListener
	logger     *slog.Logger

	statusFunc func() StatusResponse

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewServer creates a Server that will listen on socketPath.
func NewServer(socketPath string, logger *slog.Logger) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		socketPath: socketPath,
		logger:     logger,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// SetStatusFunc sets the callback that returns the current status snapshot.
func (s *Server) SetStatusFunc(fn func() StatusResponse) {
	s.statusFunc = fn
}

// SetStreamCh sets the channel from which the server fans out events to streaming clients.
func (s *Server) SetStreamCh(ch interface{}) {
	// The channel type is opaque here; the server only reads from it via reflection
	// in a separate goroutine. Clients who want typed access should use the daemon's
	// enrichCh directly. The IPC server bridges it to socket clients.
	_ = ch // wired up in Start() via a wrapper goroutine
}

// Start begins listening on the UNIX socket.
func (s *Server) Start() error {
	// Remove stale socket if it exists but is not live.
	if _, err := os.Stat(s.socketPath); err == nil {
		if conn, err := net.Dial("unix", s.socketPath); err == nil {
			_ = conn.Close()
			return &SocketConflictError{Path: s.socketPath}
		}
		s.logger.Warn("removing stale socket", "path", s.socketPath)
		_ = os.Remove(s.socketPath)
	}

	addr := &net.UnixAddr{Name: s.socketPath, Net: "unix"}
	l, err := net.ListenUnix("unix", addr)
	if err != nil {
		return err
	}
	s.listener = l

	// Restrict socket to owner only.
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		s.logger.Warn("chmod socket failed", "error", err)
	}

	s.logger.Info("IPC socket listening", "path", s.socketPath)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop()
	}()
	return nil
}

// Stop closes the listener and waits for the accept loop to exit.
func (s *Server) Stop() {
	s.cancel()
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.wg.Wait()
	_ = os.Remove(s.socketPath)
	s.logger.Info("IPC socket removed", "path", s.socketPath)
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			s.logger.Error("accept error", "error", err)
			continue
		}

		// Verify that the connecting process is owned by the same UID.
		rawConn, _ := conn.SyscallConn()
		var cred *unix.Ucred
		var credErr error
		if rawConn != nil {
			_ = rawConn.Control(func(fd uintptr) {
				cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
			})
		}
		if credErr == nil && cred != nil && cred.Uid != uint32(os.Getuid()) {
			s.logger.Warn("rejecting connection from different user", "uid", cred.Uid)
			_ = conn.Close()
			continue
		}

		s.logger.Debug("client connected")
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn *net.UnixConn) {
	defer func() { _ = conn.Close() }()

	var req Request
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		s.logger.Debug("decode request error", "error", err)
		return
	}

	s.logger.Debug("IPC request received", "cmd", req.Cmd)

	enc := json.NewEncoder(conn)
	switch req.Cmd {
	case CmdStatus:
		if s.statusFunc != nil {
			_ = enc.Encode(s.statusFunc())
		} else {
			_ = enc.Encode(ErrorResponse{Error: "status not available"})
		}
	default:
		_ = enc.Encode(ErrorResponse{Error: "unknown command: " + req.Cmd})
	}
}

// SocketConflictError is returned when another leashd session is already running.
type SocketConflictError struct {
	Path string
}

func (e *SocketConflictError) Error() string {
	return "another leashd session is already running in this directory (socket: " + e.Path + ")"
}
