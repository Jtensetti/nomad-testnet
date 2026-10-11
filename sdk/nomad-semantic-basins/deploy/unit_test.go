package deploy_test

import (
	"os"
	"strings"
	"testing"
)

// The unit is the only egress control the embedding service has: the process
// confines itself to loopback, and this stops a compromised one from changing
// its mind. A directive removed here is a hole nothing else reports, so the
// list is pinned rather than left to review.
func TestServiceUnitKeepsTheEmbeddingServiceOffTheNetwork(t *testing.T) {
	unit, err := os.ReadFile("nomad-embed-service.service")
	if err != nil {
		t.Fatal(err)
	}
	text := string(unit)

	required := []string{
		"IPAddressDeny=any",
		"IPAddressAllow=localhost",
		"RestrictAddressFamilies=AF_INET AF_INET6",
		"NoNewPrivileges=yes",
		"CapabilityBoundingSet=",
		"ProtectSystem=strict",
		"ProtectHome=yes",
		"PrivateTmp=yes",
		"RestrictNamespaces=yes",
		"MemoryDenyWriteExecute=yes",
		"SystemCallFilter=@system-service",
		"SystemCallArchitectures=native",
		"DynamicUser=yes",
	}
	for _, directive := range required {
		if !strings.Contains(text, directive) {
			t.Errorf("the unit no longer sets %s", directive)
		}
	}

	// The command line is part of the confinement: a non-loopback -listen or
	// -upstream is refused by the binary, but the unit should not be the
	// thing asking it to try.
	for _, forbidden := range []string{"-listen 0.0.0.0", "0.0.0.0:", "-upstream http://0.0.0.0"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("the unit asks the service to listen or connect off-host: %s", forbidden)
		}
	}
	if !strings.Contains(text, "-key-file ") {
		t.Error("the unit does not pass a key file, so the service would refuse to start")
	}
	if strings.Contains(text, "-generate-key") {
		t.Error("the unit runs the service in key-generation mode")
	}
}

// What this unit does not establish, said once, in the place someone reads
// before trusting it: nothing here has been verified against a running system
// in this repository. It is a hardening profile whose directives are checked
// for presence, not a sandbox whose escape has been attempted.
func TestServiceUnitIsNotClaimedToBeVerified(t *testing.T) {
	readme, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "not been exercised against a running system") {
		t.Error("the README no longer says the unit is unverified; a hardening profile " +
			"that reads as a proven sandbox is worse than none")
	}
}
