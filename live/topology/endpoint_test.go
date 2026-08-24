package topology

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The signed topology is where the network's claim about its own operators
// lives: how many there are, and that they are distinct. Everything downstream
// -- the threshold, the anytrust assumption, the peer plan -- rests on that
// claim being true of the document a node admits.
//
// These tests ask what the admission check actually enforces about an
// operator's UDP endpoint, and they were written because "two operators are two
// hosts" is checked by comparing strings, while one address has many spellings.

// verifyDocument takes a document all the way from attestation to admission
// and returns the first error any stage raised.
//
// Every stage's error counts as a refusal, not just Verify's. The document
// checks run inside Attest as well, so a helper that fataled on an Attest
// error would report a correct refusal as a broken test -- which is exactly
// what the first version of this file did.
func verifyDocument(t *testing.T, document Document, identities map[string]ed25519.PrivateKey) error {
	t.Helper()
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attested := document
	for _, operator := range document.Operators {
		attested, err = Attest(attested, operator.ID, identities[operator.ID])
		if err != nil {
			return err
		}
	}
	signed, err := Finalize(attested, authorityPrivate)
	if err != nil {
		return err
	}
	encoded, err := Encode(signed)
	if err != nil {
		return err
	}
	_, err = Verify(encoded, authorityPublic, time.Now())
	return err
}

// IPv6 must be a first-class operator address, not something the document
// format happens to tolerate. B-12 names it, and a validator that silently
// only accepted dotted quads would make the network IPv4-only by construction
// without anyone deciding that.
func TestOperatorEndpointsMayBeIPv6OrMixed(t *testing.T) {
	for name, endpoints := range map[string][]string{
		"all IPv6":   {"[::1]:4200", "[2001:db8::1]:4201", "[fe80::1]:4202"},
		"mixed":      {"127.0.0.1:4200", "[2001:db8::2]:4201", "10.0.0.5:4202"},
		"compressed": {"[2001:db8:0:0:0:0:0:1]:4200", "[2001:db8::2]:4201", "127.0.0.1:4202"},
	} {
		t.Run(name, func(t *testing.T) {
			document, identities := unattestedDocument(t, "endpoint-test", 3)
			for index, endpoint := range endpoints {
				document.Operators[index].Endpoint = endpoint
			}
			if err := verifyDocument(t, document, identities); err != nil {
				t.Fatalf("a topology with %s endpoints was refused: %v", name, err)
			}
			// And each must parse as an address, or admitting it only defers
			// the failure to the moment a node tries to use it.
			for _, endpoint := range endpoints {
				if _, err := netip.ParseAddrPort(endpoint); err != nil {
					t.Fatalf("admitted endpoint %q is not an address: %v", endpoint, err)
				}
			}
		})
	}
}

func TestMalformedEndpointsAreRefused(t *testing.T) {
	for name, endpoint := range map[string]string{
		"IPv6 without brackets": "::1:4200",
		"no port":               "127.0.0.1",
		"empty host":            ":4200",
		"empty port":            "127.0.0.1:",
		"empty":                 "",
		"not an address":        "this is not an endpoint",
	} {
		t.Run(name, func(t *testing.T) {
			document, identities := unattestedDocument(t, "endpoint-test", 3)
			document.Operators[0].Endpoint = endpoint
			if err := verifyDocument(t, document, identities); err == nil {
				t.Fatalf("a topology naming the endpoint %q was admitted", endpoint)
			}
		})
	}
}

// One socket address written two ways is one operator.
//
// The claim is deliberately about socket addresses and nothing larger. Two
// operators on one host at different ports are still two entries here, and this
// package's own fixtures rely on that, so nothing below establishes that
// operators are independent machines or independent trust domains -- only that
// the document does not count one endpoint twice.
//
// Exact-string comparison did not establish even that. One address has many
// spellings, and the sharpest pair is not two IPv6 forms but an IPv4 address
// and its IPv4-mapped IPv6 form, which look nothing alike.
func TestOneSocketAddressInTwoSpellingsIsOneOperator(t *testing.T) {
	for name, pair := range map[string][2]string{
		"IPv6 compressed and expanded":  {"[::1]:4200", "[0:0:0:0:0:0:0:1]:4200"},
		"IPv6 with and without padding": {"[2001:db8::1]:4200", "[2001:0db8:0000:0000:0000:0000:0000:0001]:4200"},
		"IPv4 and its IPv4-mapped form": {"127.0.0.1:4200", "[::ffff:127.0.0.1]:4200"},
	} {
		t.Run(name, func(t *testing.T) {
			// Establish that the pair really is one address, or the case
			// proves nothing. netip parses without a resolver: this suite
			// asserts that verification performs no lookup, so it must not
			// perform one itself to make its point.
			if !sameAddress(t, pair[0], pair[1]) {
				t.Fatalf("%q and %q are different addresses, so this case tests nothing",
					pair[0], pair[1])
			}

			document, identities := unattestedDocument(t, "endpoint-test", 3)
			document.Operators[0].Endpoint = pair[0]
			document.Operators[1].Endpoint = pair[1]
			requireDuplicate(t, verifyDocument(t, document, identities), pair)
		})
	}
}

// A port of zero means "any port" to the operating system, so it names no
// endpoint a peer can send to. Admitting it defers the failure to the first
// node that tries to use the document.
func TestAZeroPortEndpointIsRefused(t *testing.T) {
	for name, endpoint := range map[string]string{
		"IPv4": "127.0.0.1:0",
		"IPv6": "[::1]:0",
	} {
		t.Run(name, func(t *testing.T) {
			document, identities := unattestedDocument(t, "endpoint-test", 3)
			document.Operators[0].Endpoint = endpoint
			if err := verifyDocument(t, document, identities); err == nil {
				t.Fatalf("a topology naming the port-zero endpoint %q was admitted", endpoint)
			}
		})
	}
}

// The identical-string case must keep failing: it is the check the two tests
// above extend, and losing it would make them the only protection.
func TestTwoOperatorsCannotShareAnIdenticalEndpoint(t *testing.T) {
	document, identities := unattestedDocument(t, "endpoint-test", 3)
	document.Operators[1].Endpoint = document.Operators[0].Endpoint
	err := verifyDocument(t, document, identities)
	if err == nil {
		t.Fatal("a topology with two identical operator endpoints was admitted")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// Hostnames must keep working: the Compose deployment names operators by
// service name, so requiring literal addresses would be a deployment change
// dressed up as a validation fix.
//
// What a document cannot establish about hostnames is stated rather than
// implied: two different names pointing at one machine are a fact about DNS,
// and canonicalisation here is deliberately limited to case.
func TestHostnameEndpointsRemainValid(t *testing.T) {
	t.Run("the Compose deployment's service names", func(t *testing.T) {
		document, identities := unattestedDocument(t, "endpoint-test", 3)
		for index, endpoint := range []string{"operator-a:4200", "operator-b:4200", "operator-c:4200"} {
			document.Operators[index].Endpoint = endpoint
		}
		if err := verifyDocument(t, document, identities); err != nil {
			t.Fatalf("the Compose deployment's hostname endpoints were refused: %v", err)
		}
	})

	t.Run("a port with a leading zero is the same port", func(t *testing.T) {
		document, identities := unattestedDocument(t, "endpoint-test", 3)
		document.Operators[0].Endpoint = "10.0.0.1:4200"
		document.Operators[1].Endpoint = "10.0.0.1:04200"
		requireDuplicate(t, verifyDocument(t, document, identities),
			[2]string{"10.0.0.1:4200", "10.0.0.1:04200"})
	})
}

// A zone distinguishes real interfaces, but live/node keys inbound peers on IP
// and port with the zone dropped (udpAddressKey), so two zone-distinct peers
// are indistinguishable as datagram sources at runtime. An earlier version of
// this test required such a pair to be *admitted*, which locked in a promise
// the node does not keep: Verify would bless a topology that node.New refuses
// to start on, and inbound authentication would treat the two peers as one.
//
// Admission now refuses a zone rather than flattening it silently.
func TestAZonedAddressIsRefusedRatherThanPromisingWhatTheNodeCannotDo(t *testing.T) {
	document, identities := unattestedDocument(t, "endpoint-test", 3)
	document.Operators[0].Endpoint = "[fe80::1%eth0]:4200"
	if err := verifyDocument(t, document, identities); err == nil {
		t.Fatal("a zoned endpoint was admitted, but live/node cannot tell two zones apart")
	}
}

// One hostname in two spellings. A trailing dot is the root label, so
// operator-a. and operator-a are one name -- and hostnames are the form the
// Compose deployment actually uses, so this is the spelling class that matters
// most in practice rather than the IPv6 ones.
func TestOneHostnameInTwoSpellingsIsOneOperator(t *testing.T) {
	for name, pair := range map[string][2]string{
		"trailing dot":     {"operator-a:4200", "operator-a.:4200"},
		"case":             {"operator-a:4200", "OPERATOR-A:4200"},
		"both":             {"operator-a:4200", "Operator-A.:4200"},
		"localhost vs 127": {"localhost:4200", "127.0.0.1:4200"},
		"localhost vs ::1": {"localhost:4200", "[::1]:4200"},
		"two loopbacks":    {"127.0.0.1:4200", "127.0.0.2:4200"},
	} {
		t.Run(name, func(t *testing.T) {
			document, identities := unattestedDocument(t, "endpoint-test", 3)
			document.Operators[0].Endpoint = pair[0]
			document.Operators[1].Endpoint = pair[1]
			requireDuplicate(t, verifyDocument(t, document, identities), pair)
		})
	}
}

// A host that is not a valid address must not be reinterpreted as a hostname.
// Each of these was admitted before the grammar was tightened, and each is read
// as a different host by some other implementation: a NUL truncates in any C
// string, 2130706433 and 0177.0.0.1 are 127.0.0.1 under inet_aton and
// unresolvable under Go's parser, and [foo:bar] is not an address at all.
//
// This is the same cross-parser divergence strictjson.RejectDuplicateKeys
// refuses for JSON: a document one implementation admits as three operators and
// another as two has not been agreed on.
func TestHostsThatDifferentParsersReadDifferentlyAreRefused(t *testing.T) {
	for name, host := range map[string]string{
		"embedded NUL":          "operator-a\x00",
		"trailing space":        "operator-a ",
		"leading space":         " operator-a",
		"bracketed non-address": "[foo:bar]",
		"integer address":       "2130706433",
		"octal dotted quad":     "0177.0.0.1",
		"underscore":            "operator_a",
		"leading hyphen label":  "-operator-a",
		"trailing hyphen label": "operator-a-",
		"empty label":           "operator..a",
		"unicode":               "operatör-a",
		"kelvin sign":           "operator-\u212a",
		"over-long":             strings.Repeat("a", 254),
		"over-long label":       strings.Repeat("b", 64),
	} {
		t.Run(name, func(t *testing.T) {
			document, identities := unattestedDocument(t, "endpoint-test", 3)
			document.Operators[0].Endpoint = host + ":4200"
			if err := verifyDocument(t, document, identities); err == nil {
				t.Fatalf("the host %q was admitted", host)
			}
		})
	}
}

// Addresses that name nothing a peer can send to are refused for the same
// reason port zero is. 0.0.0.0 and [::] are the natural typo when a listen
// flag is copied into an endpoint field, and deploy/compose.yaml uses :4200.
func TestAddressesNoPeerCanSendToAreRefused(t *testing.T) {
	for name, endpoint := range map[string]string{
		"IPv4 unspecified": "0.0.0.0:4200",
		"IPv6 unspecified": "[::]:4200",
		"IPv4 broadcast":   "255.255.255.255:4200",
		"IPv4 multicast":   "224.0.0.1:4200",
		"IPv6 multicast":   "[ff02::1]:4200",
	} {
		t.Run(name, func(t *testing.T) {
			document, identities := unattestedDocument(t, "endpoint-test", 3)
			document.Operators[0].Endpoint = endpoint
			if err := verifyDocument(t, document, identities); err == nil {
				t.Fatalf("the endpoint %q was admitted", endpoint)
			}
		})
	}
}

// requireDuplicate asserts a refusal is the duplicate refusal, not some other
// error that happens to fire first.
//
// The pair tests originally asserted only err != nil, and one sub-case duly
// passed for an unrelated reason: validCeremonyURL refuses http for a non-
// loopback host, so a DKG endpoint of http://OPERATOR-A:4300 was refused as a
// single operator and the case would have passed with the canonicalisation
// deleted entirely.
func requireDuplicate(t *testing.T, err error, pair [2]string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%q and %q were admitted as two operators", pair[0], pair[1])
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("%q and %q were refused, but not as a duplicate: %v", pair[0], pair[1], err)
	}
}

// sameAddress reports whether two endpoint spellings denote one socket address,
// using netip so no resolver is involved.
func sameAddress(t *testing.T, left, right string) bool {
	t.Helper()
	first, err := netip.ParseAddrPort(left)
	if err != nil {
		t.Fatalf("%q: %v", left, err)
	}
	second, err := netip.ParseAddrPort(right)
	if err != nil {
		t.Fatalf("%q: %v", right, err)
	}
	return netip.AddrPortFrom(first.Addr().Unmap(), first.Port()) ==
		netip.AddrPortFrom(second.Addr().Unmap(), second.Port())
}
