//go:build linux || darwin || freebsd || netbsd || openbsd

package rotation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type ProcessLock struct {
	file *os.File
}

// AcquireProcessLock holds a kernel-backed exclusive advisory lock for the
// controller lifetime. The lock survives a persistent lock filename but is
// automatically released by the kernel if the process crashes.
func AcquireProcessLock(stateRoot string) (*ProcessLock, error) {
	if err := ensureRealDirectory(stateRoot); err != nil {
		return nil, err
	}
	path := filepath.Join(stateRoot, "controller.lock")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open rotation controller lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("create rotation controller lock file handle")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("rotation controller lock must be a regular file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errors.New("another rotation controller already owns this state root")
		}
		return nil, fmt.Errorf("lock rotation controller state: %w", err)
	}
	return &ProcessLock{file: file}, nil
}

func (lock *ProcessLock) Release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	fd := int(lock.file.Fd())
	unlockErr := unix.Flock(fd, unix.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
