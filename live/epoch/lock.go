package epoch

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// chainLock is an advisory whole-directory lock held for the duration of a
// mutating chain operation. A process mutex alone is not enough: the
// specification expects every verifier to keep a store, and a node plus an
// operator CLI on one host is the ordinary deployment. Without cross-process
// exclusion two instances can race on the same directory, and a genuine
// conflict surfaces as a filesystem error rather than as equivocation.
type chainLock struct {
	file *os.File
}

func acquireChainLock(root string) (*chainLock, error) {
	path := filepath.Join(root, "LOCK")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &chainLock{file: file}, nil
}

func (lock *chainLock) release() error {
	if lock == nil || lock.file == nil {
		return errors.New("chain lock is not held")
	}
	flockErr := unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if flockErr != nil {
		return flockErr
	}
	return closeErr
}
