package telemetry_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-testnet/live/telemetry"
)

// buildCrasher compiles the helper program under testdata. The measurement
// needs a real process: the testing framework wraps a panic in its own
// recover-and-repanic path and prints a dump regardless of what the program
// asked for, so a test binary cannot observe this.
func buildCrasher(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "crasher")
	build := exec.Command("go", "build", "-o", binary, "./testdata/crasher")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the crash helper failed: %v\n%s", err, output)
	}
	return binary
}

func runCrasher(t *testing.T, binary string, environment ...string) string {
	t.Helper()
	command := exec.Command(binary)
	command.Env = append(os.Environ(), environment...)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("the helper process did not crash, so nothing was measured")
	}
	return string(output)
}

// Under the deployment setting, a panic prints the panic value and nothing
// that could carry memory contents.
func TestCrashUnderGotracebackNonePrintsNoDump(t *testing.T) {
	text := runCrasher(t, buildCrasher(t), telemetry.TracebackVariable+"=none")
	if !strings.Contains(text, "deliberate crash for the telemetry boundary test") {
		t.Fatalf("the panic value is missing, so the wrong output was read:\n%s", text)
	}
	for _, forbidden := range []string{
		"goroutine 1 [running]", "panicWithSecretAlive(", "created by ", ".go:",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("crash output contains %q, so a goroutine dump was printed:\n%s",
				forbidden, text)
		}
	}
	if strings.Contains(text, "SUPERSECRETKEYMATERIAL") {
		t.Fatal("the secret itself reached the crash output")
	}
}

// Without it, the dump appears -- so the test above measures the setting
// rather than an accident of this program's shape. This also records the
// finding that made the control a deployment control: an in-process
// debug.SetTraceback("none") does not suppress this, and the earlier version
// of this package pretended otherwise.
func TestCrashWithoutTheSettingPrintsFrameArguments(t *testing.T) {
	text := runCrasher(t, buildCrasher(t), telemetry.TracebackVariable+"=")
	if !strings.Contains(text, "goroutine 1 [running]") {
		t.Fatalf("no dump even unprotected, so the protected case proves nothing:\n%s", text)
	}
	if !strings.Contains(text, "panicWithSecretAlive(0x") &&
		!strings.Contains(text, "panicWithSecretAlive({0x") {
		t.Fatalf("frame arguments were not printed, so the risk this guards is not "+
			"demonstrated:\n%s", text)
	}
	if !strings.Contains(text, "will print goroutine stacks") {
		t.Fatal("the process did not warn that its crash output was unprotected")
	}
}

func TestSuppressionIsReportedFromTheEnvironment(t *testing.T) {
	t.Setenv(telemetry.TracebackVariable, "none")
	if !telemetry.CrashDumpsSuppressed() {
		t.Fatal("none was not recognised as suppressed")
	}
	var warnings strings.Builder
	if !telemetry.WarnIfCrashDumpsEnabled(&warnings) || warnings.String() != "" {
		t.Fatalf("a suppressed process warned anyway: %q", warnings.String())
	}
	for _, level := range []string{"", "single", "all", "system", "crash", "1"} {
		t.Setenv(telemetry.TracebackVariable, level)
		if telemetry.CrashDumpsSuppressed() {
			t.Fatalf("%q was treated as suppressed", level)
		}
		warnings.Reset()
		if telemetry.WarnIfCrashDumpsEnabled(&warnings) {
			t.Fatalf("%q reported as suppressed", level)
		}
		if !strings.Contains(warnings.String(), telemetry.TracebackVariable) {
			t.Fatalf("%q produced no usable warning: %q", level, warnings.String())
		}
	}
}
