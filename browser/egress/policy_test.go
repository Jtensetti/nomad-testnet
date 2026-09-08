package egress

import (
	"errors"
	"testing"
)

func TestEveryBrowserNetworkCapabilityIsDenied(t *testing.T) {
	capabilities := ForbiddenCapabilities()
	if len(capabilities) != 13 {
		t.Fatalf("capability inventory has %d entries", len(capabilities))
	}
	for _, capability := range capabilities {
		if err := (Policy{}).Authorize(capability); !errors.Is(err, ErrDenied) {
			t.Fatalf("%s was not denied: %v", capability, err)
		}
	}
}

func TestRendererURLPolicyHasNoOrdinaryNetworkFallback(t *testing.T) {
	for _, raw := range []string{
		"https://example.com/",
		"http://127.0.0.1/",
		"ws://example.com/",
		"wss://example.com/",
		"ftp://example.com/",
		"file:///etc/passwd",
		"blob:https://example.com/id",
		"javascript:fetch('https://example.com')",
	} {
		if err := (Policy{}).CheckRendererURL(raw); !errors.Is(err, ErrDenied) {
			t.Fatalf("%q was not denied: %v", raw, err)
		}
	}
	for _, raw := range []string{"nomad:/index.html", "data:text/plain,local", "about:blank"} {
		if err := (Policy{}).CheckRendererURL(raw); err != nil {
			t.Fatalf("%q was not allowed: %v", raw, err)
		}
	}
}
