package epoch

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The chain lock is the only thing between two processes mutating one epoch
// chain directory, and the specification expects that deployment: a node and
// an operator CLI on one host. It had no test on either platform, and the
// Windows half had never executed at all -- it compiles under GOOS=windows in
// CI and no runner has ever run it.
//
// Exclusion between processes cannot be shown from inside one process, so this
// re-executes the test binary in a helper role. TestMain dispatches that role,
// rather than a test function that skips when it is not the helper, so there is
// no test here that can quietly do nothing.

const (
	helperRootVariable = "NOMAD_CHAIN_LOCK_HELPER_ROOT"

	// The parent removes heldMarker immediately before it releases. A helper
	// that acquires while the marker is still there acquired a lock somebody
	// else was holding, which is the failure this exists to catch.
	heldMarker = "held-by-parent"

	// The helper creates readyMarker immediately before it blocks. Without it
	// the parent cannot tell "the helper waited" from "the helper had not
	// started yet", and the test would pass on a lock that excludes nothing.
	readyMarker = "helper-ready"
)

func TestMain(m *testing.M) {
	root := os.Getenv(helperRootVariable)
	if root == "" {
		os.Exit(m.Run())
	}
	os.Exit(runChainLockHelper(root))
}

// runChainLockHelper reports through its exit code rather than its output, so
// a helper that failed to start cannot be read as one that reported success.
func runChainLockHelper(root string) int {
	if err := os.WriteFile(filepath.Join(root, readyMarker), []byte("ready"), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "helper could not announce itself: %v\n", err)
		return 2
	}
	start := time.Now()
	lock, err := acquireChainLock(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper could not acquire the lock: %v\n", err)
		return 3
	}
	_, statErr := os.Stat(filepath.Join(root, heldMarker))
	waited := time.Since(start)
	if err := lock.release(); err != nil {
		fmt.Fprintf(os.Stderr, "helper could not release the lock: %v\n", err)
		return 4
	}
	if statErr == nil {
		fmt.Fprintf(os.Stderr, "helper acquired the lock after %s while the parent "+
			"was still holding it\n", waited)
		return 5
	}
	if !errors.Is(statErr, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "helper could not read the marker: %v\n", statErr)
		return 6
	}
	fmt.Fprintf(os.Stdout, "helper acquired the lock after %s\n", waited)
	return 0
}

type helperProcess struct {
	done   <-chan error
	output *bytes.Buffer
}

// startHelper runs this test binary again with the helper variable set, and
// returns once the helper says it is about to block.
func startHelper(t *testing.T, root string) helperProcess {
	t.Helper()
	output := new(bytes.Buffer)
	command := exec.Command(os.Args[0])
	command.Env = append(os.Environ(), helperRootVariable+"="+root)
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		t.Fatalf("could not start the helper process: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
	})

	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, readyMarker)); err == nil {
			return helperProcess{done: done, output: output}
		}
		select {
		case err := <-done:
			t.Fatalf("the helper exited before it reached the lock: %v\n%s", err, output)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the helper never announced itself\n%s", output)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestTheChainLockExcludesASecondProcess(t *testing.T) {
	root := t.TempDir()
	lock, err := acquireChainLock(root)
	if err != nil {
		t.Fatalf("the parent could not take the lock: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, heldMarker), []byte("held"), 0o600); err != nil {
		t.Fatal(err)
	}

	helper := startHelper(t, root)
	const holdFor = 400 * time.Millisecond
	select {
	case err := <-helper.done:
		t.Fatalf("a second process got the lock while this one held it: %v\n%s",
			err, helper.output)
	case <-time.After(holdFor):
	}

	if err := os.Remove(filepath.Join(root, heldMarker)); err != nil {
		t.Fatal(err)
	}
	if err := lock.release(); err != nil {
		t.Fatalf("the parent could not release the lock: %v", err)
	}

	select {
	case err := <-helper.done:
		if err != nil {
			t.Fatalf("the helper failed after the lock was released: %v\n%s",
				err, helper.output)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the helper never got the lock after it was released\n%s", helper.output)
	}
}

// The control. If the helper could never acquire, the test above would pass by
// the helper simply not finishing early -- so the same helper, against a
// directory nobody has locked, must acquire and exit cleanly.
func TestTheHelperAcquiresALockNobodyIsHolding(t *testing.T) {
	root := t.TempDir()
	helper := startHelper(t, root)
	select {
	case err := <-helper.done:
		if err != nil {
			t.Fatalf("the helper could not take an unheld lock: %v\n%s", err, helper.output)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the helper blocked on a lock nobody was holding\n%s", helper.output)
	}
}

// Releasing twice must say so rather than report success, because a second
// release that silently succeeds is one that could be unlocking a lock some
// later operation took.
func TestReleasingAChainLockTwiceIsAnError(t *testing.T) {
	root := t.TempDir()
	lock, err := acquireChainLock(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.release(); err != nil {
		t.Fatal(err)
	}
	if err := lock.release(); err == nil {
		t.Fatal("releasing a lock that is not held reported success")
	}
}
