//go:build windows

package epoch

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// chainLock is the Windows half of the cross-process chain lock. See
// lock_unix.go for why the lock exists at all.
//
// LockFileEx is the closest equivalent to flock here: with
// LOCKFILE_EXCLUSIVE_LOCK and no LOCKFILE_FAIL_IMMEDIATELY it blocks until the
// lock is available, which is the behaviour the unix path relies on. It is
// mandatory rather than advisory on Windows, which is stricter than the unix
// side and not weaker, so nothing that depends on exclusion loses a guarantee.
//
// The lock covers one byte rather than the whole file. That is the documented
// idiom: a zero-length range locks nothing, and the file is only ever a lock
// token, so a single byte is the whole of what needs excluding.
type chainLock struct {
	file *os.File
}

func acquireChainLock(root string) (*chainLock, error) {
	path := filepath.Join(root, "LOCK")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, overlapped); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &chainLock{file: file}, nil
}

func (lock *chainLock) release() error {
	if lock == nil || lock.file == nil {
		return errors.New("chain lock is not held")
	}
	overlapped := new(windows.Overlapped)
	unlockErr := windows.UnlockFileEx(windows.Handle(lock.file.Fd()), 0, 1, 0, overlapped)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
