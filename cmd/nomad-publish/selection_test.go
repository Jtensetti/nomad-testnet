package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Which entry operator a publisher speaks to is a configuration value, decided
// once from a flag and the signed topology, and it must stay one.
//
// This is a discovery decision on the publishing side, and the invariant covers
// it exactly as it covers relay peer selection: if the entry operator were
// chosen per object, per fragment, per queue depth or per failure, then which
// operator received a datagram would be a function of private publication
// activity -- visible to anyone watching which of the network's addresses this
// host sends to, without opening a single cell.
//
// The relay side already has this as a test (live/epoch's plan tests, and
// live/node's peer-set tests). The publisher side had it only as the shape of
// the code, which is the kind of property that survives until someone adds a
// sensible-sounding "fail over to another entry operator" and no test objects.
func TestTheEntryOperatorIsChosenOnceFromConfiguration(t *testing.T) {
	fileSet := token.NewFileSet()
	packages, err := parser.ParseDir(fileSet, ".", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, parsed := range packages {
		for name, file := range parsed.Files {
			if name == "selection_test.go" {
				continue
			}
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				if identifier, ok := call.Fun.(*ast.Ident); ok && identifier.Name == "entryOperator" {
					found++
					if len(call.Args) != 2 {
						t.Errorf("%s: entryOperator takes %d arguments; it must take "+
							"the signed topology and the configured identifier and "+
							"nothing else", name, len(call.Args))
					}
				}
				return true
			})
		}
	}
	if found != 1 {
		t.Fatalf("entryOperator is called %d times; one call is what makes the "+
			"choice a configuration value rather than a runtime decision", found)
	}
}
