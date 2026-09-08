//go:build windows

package durable

import (
	"fmt"
	"os"
)

// Directory does not flush on Windows, because Windows does not offer the
// operation. FlushFileBuffers on a directory handle fails with
// ERROR_ACCESS_DENIED, which is the "Access is denied" that os.File.Sync
// reports there, and there is no supported call that does what fsync on a
// directory does on unix.
//
// This is a weaker guarantee and it is not disguised as an equal one: on
// Windows a rename's durability rests on NTFS metadata journaling rather than
// on anything this code did. That is why Windows is not a supported operator
// platform. It is in the build matrix so the code keeps compiling for it, and
// the epoch store's tests run there so the platform-specific paths execute;
// neither is a claim that an operator should run a node on it.
//
// The checks around the flush are deliberately kept, so a missing directory or
// a path that names a file is an error on every platform. A Windows build that
// accepted paths a unix build rejects would turn a portability difference into
// a difference in what the code validates.
func Directory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s: %w", path, ErrNotADirectory)
	}
	return nil
}
