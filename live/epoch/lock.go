package epoch

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// chainLock is an advisory whole-directory lock. Writers take it exclusively;
// production readers take it shared. The distinction matters because node and
// share services receive the verified epoch-chain volume read-only. Requiring
// O_RDWR merely to refresh immutable descriptors would unnecessarily give a
// serving process write capability and fails on a correctly hardened mount.
type chainLock struct {
	file *os.File
}

// acquireChainLock is the writer lock. Mutating operations may create the
// lock file because they already require a writable epoch-chain store.
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

// acquireChainReadLock synchronizes a reader with an in-progress writer
// without requiring any filesystem write capability. The lock file must have
// been created by initialization/import before a chain is exposed read-only;
// its absence therefore fails closed instead of silently reading unlocked.
func acquireChainReadLock(root string) (*chainLock, error) {
	path := filepath.Join(root, "LOCK")
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_SH); err != nil {
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
