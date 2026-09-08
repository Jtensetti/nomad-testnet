//go:build unix

package durable

import (
	"fmt"
	"os"
)

// Directory flushes a directory's own metadata.
//
// This is what makes a create or a rename in it survive a crash. Flushing the
// file writes its contents; flushing the directory writes the name that points
// at them, and without the second a crash can leave a file whose data is on
// disk and whose name is not.
func Directory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s: %w", path, ErrNotADirectory)
	}
	handle, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := handle.Sync()
	closeErr := handle.Close()
	if syncErr != nil {
		return fmt.Errorf("sync %s: %w", path, syncErr)
	}
	return closeErr
}
