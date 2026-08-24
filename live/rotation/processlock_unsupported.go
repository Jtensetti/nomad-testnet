//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package rotation

import "errors"

type ProcessLock struct{}

func AcquireProcessLock(string) (*ProcessLock, error) {
	return nil, errors.New("rotation controller requires a supported kernel-backed process lock")
}

func (lock *ProcessLock) Release() error { return nil }
