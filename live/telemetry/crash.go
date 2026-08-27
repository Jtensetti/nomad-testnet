package telemetry

import (
	"fmt"
	"io"
	"os"
)

// TracebackVariable is the Go runtime's own control over crash output.
const TracebackVariable = "GOTRACEBACK"

// CrashDumpsSuppressed reports whether an unrecovered panic in this process
// will print goroutine stacks.
//
// A Go panic normally prints a dump in which each frame's arguments appear as
// raw machine words. For a process holding an operator identity key, a
// threshold share or relayed ciphertext, those words can be key material, and
// an init system retains whatever a crashing service wrote. The production
// criterion says crash data cannot contain secret keys, so a Nomad process is
// meant to run with dumps off.
//
// It is the environment variable and only the environment variable.
// debug.SetTraceback("none") looks like it does this and does not: measured on
// go1.24.7 and go1.25.0, a process that calls it still prints "goroutine 1
// [running]" and its frames' argument words, while the same binary under
// GOTRACEBACK=none prints the panic value alone. The runtime reads the
// variable at startup, so nothing in-process can substitute for setting it,
// which makes this a deployment control that the program can verify but not
// impose.
func CrashDumpsSuppressed() bool {
	return os.Getenv(TracebackVariable) == "none"
}

// WarnIfCrashDumpsEnabled writes a startup warning when this process would
// print goroutine stacks on a panic, and reports whether dumps are suppressed.
//
// It warns rather than refusing to start. A node that exits because of a
// missing environment variable is a node that is not carrying cover traffic,
// and the difference between "might print memory contents while crashing" and
// "is not running" is not obviously in the first one's favour. The warning is
// on stderr at startup so the condition is visible in the same log that would
// receive the dump.
func WarnIfCrashDumpsEnabled(warnings io.Writer) bool {
	if CrashDumpsSuppressed() {
		return true
	}
	if warnings != nil {
		fmt.Fprintf(warnings,
			"%s is not \"none\": a panic in this process will print goroutine stacks, "+
				"whose frame arguments may include key material. Set %s=none in the "+
				"service definition.\n", TracebackVariable, TracebackVariable)
	}
	return false
}
