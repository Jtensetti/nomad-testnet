package deploy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The production goal asks for an exact external operator onboarding package,
// on the grounds that this project cannot supply independent operators (EB-2)
// and the least it can do is hand a real one instructions that work.
//
// Instructions that work are a testable property, and nothing tested it. Every
// command, subcommand and flag these documents tell an operator to run is a
// claim about a binary in this repository, and a rename would leave an
// external operator following instructions for something that is not there --
// discovered by them, during a ceremony, with key material on the table.

// operatorFacing are the documents an external operator is handed or follows
// under pressure.
var operatorFacing = []string{
	"OPERATOR_ONBOARDING.md",
	"RECOVERY_RUNBOOK.md",
	"RECOVERY.md",
	"MULTI_OPERATOR.md",
}

// notCommands are nomad-prefixed tokens in those documents that name something
// other than a binary. Each is here because it is genuinely not a command, and
// the list is short on purpose: an unknown token should fail rather than be
// waved through.
var notCommands = map[string]string{
	"nomad-protocol":    "the specifications repository",
	"nomad-live":        "the Compose project and image name",
	"nomad-node-health": "the health file a node writes, not a binary",
}

var nomadToken = regexp.MustCompile(`nomad-[a-z0-9-]+`)

func operatorDocuments(t *testing.T) map[string]string {
	t.Helper()
	found := map[string]string{}
	for _, name := range operatorFacing {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s is named as operator-facing and is not here: %v", name, err)
		}
		found[name] = string(content)
	}
	return found
}

func TestEveryCommandTheOperatorDocumentsNameExists(t *testing.T) {
	checked := 0
	for name, text := range operatorDocuments(t) {
		for _, token := range nomadToken.FindAllString(text, -1) {
			if reason, known := notCommands[token]; known {
				_ = reason
				continue
			}
			checked++
			if _, err := os.Stat(filepath.Join("..", "cmd", token)); err != nil {
				t.Errorf("%s tells an operator to run %s, and this repository builds "+
					"no such command. Either it was renamed and the instructions were "+
					"not, or it is not a command and belongs in notCommands with the "+
					"reason.", name, token)
			}
		}
	}
	if checked < 5 {
		t.Fatalf("only %d command references were checked; the operator documents "+
			"name more than that, so the scan is not reading them", checked)
	}
}

// commandInterface reads a command's subcommands and long flags from its
// source, which is what an operator's instructions have to agree with.
func commandInterface(t *testing.T, command string) (subcommands, flags map[string]bool) {
	t.Helper()
	subcommands, flags = map[string]bool{}, map[string]bool{}
	directory := filepath.Join("..", "cmd", command)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("reading %s: %v", directory, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(),
			filepath.Join(directory, entry.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", entry.Name(), err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.CaseClause:
				for _, expression := range typed.List {
					if literal, ok := expression.(*ast.BasicLit); ok && literal.Kind == token.STRING {
						if value, err := strconv.Unquote(literal.Value); err == nil &&
							value != "" && !strings.HasPrefix(value, "-") {
							subcommands[value] = true
						}
					}
				}
			case *ast.CallExpr:
				selector, ok := typed.Fun.(*ast.SelectorExpr)
				if !ok || len(typed.Args) == 0 {
					return true
				}
				switch selector.Sel.Name {
				case "String", "Bool", "Duration", "Int", "Int64", "Uint", "Float64":
					if literal, ok := typed.Args[0].(*ast.BasicLit); ok && literal.Kind == token.STRING {
						if value, err := strconv.Unquote(literal.Value); err == nil {
							flags[value] = true
						}
					}
				}
			}
			return true
		})
	}
	return subcommands, flags
}

// The control. Both maps above are read from source, and a reader that found
// nothing would let every documented invocation pass.
func TestTheInterfaceReaderFindsWhatIsThere(t *testing.T) {
	subcommands, flags := commandInterface(t, "nomad-operator")
	for _, expected := range []string{"init", "inspect", "attest", "verify", "erase"} {
		if !subcommands[expected] {
			names := make([]string, 0, len(subcommands))
			for name := range subcommands {
				names = append(names, name)
			}
			sort.Strings(names)
			t.Fatalf("the reader did not find nomad-operator's %q subcommand; it saw %v",
				expected, names)
		}
	}
	for _, expected := range []string{"secret", "topology", "out"} {
		if !flags[expected] {
			t.Fatalf("the reader did not find nomad-operator's --%s flag", expected)
		}
	}
}

var documentedFlag = regexp.MustCompile(`--([a-z][a-z0-9-]*)`)

func TestEverySubcommandAndFlagTheOperatorDocumentsNameExists(t *testing.T) {
	checked := 0
	for name, text := range operatorDocuments(t) {
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "`"))
			command := nomadToken.FindString(trimmed)
			if command == "" || !strings.HasPrefix(trimmed, command) {
				continue
			}
			if _, known := notCommands[command]; known {
				continue
			}
			if _, err := os.Stat(filepath.Join("..", "cmd", command)); err != nil {
				continue // reported by the test above
			}
			subcommands, flags := commandInterface(t, command)
			fields := strings.Fields(trimmed)
			for index := range fields {
				// Inline mentions carry the closing backtick and the sentence's
				// punctuation: `nomad-topology draft`. The first version read
				// that as a subcommand named "draft`." and reported two
				// failures against subcommands that exist.
				fields[index] = strings.Trim(fields[index], "`.,;:")
			}
			if len(fields) > 1 && !strings.HasPrefix(fields[1], "-") && len(subcommands) > 0 {
				checked++
				if !subcommands[fields[1]] {
					t.Errorf("%s tells an operator to run `%s %s`, and %s has no such "+
						"subcommand", name, command, fields[1], command)
				}
			}
			for _, match := range documentedFlag.FindAllStringSubmatch(trimmed, -1) {
				checked++
				if !flags[match[1]] {
					t.Errorf("%s tells an operator to pass --%s to %s, which defines no "+
						"such flag", name, match[1], command)
				}
			}
		}
	}
	if checked < 10 {
		t.Fatalf("only %d subcommands and flags were checked; these documents show "+
			"more invocations than that, so the scan is not finding them", checked)
	}
}
