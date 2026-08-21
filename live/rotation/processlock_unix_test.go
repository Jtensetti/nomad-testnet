//go:build linux || darwin || freebsd || netbsd || openbsd

package rotation

import "testing"

func TestProcessLockIsExclusiveAndCrashStyleReleaseIsReusable(t *testing.T) {
	root := t.TempDir()
	first, err := AcquireProcessLock(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireProcessLock(root); err == nil {
		_ = first.Release()
		t.Fatal("second controller acquired the same state-root lock")
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireProcessLock(root)
	if err != nil {
		t.Fatalf("lock could not be reacquired after release: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
}
