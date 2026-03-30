package bpf

import (
	"errors"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// setRlimitInfinity removes the RLIMIT_MEMLOCK limit so the BPF subsystem
// can allocate large maps.
func setRlimitInfinity() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
}

// isVerifierError checks if err is an ebpf.VerifierError and fills ve.
func isVerifierError(err error, ve **ebpf.VerifierError) bool {
	return errors.As(err, ve)
}
