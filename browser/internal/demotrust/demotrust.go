// Package demotrust holds the publisher key the Go tests verify against.
//
// It used to be a shared anchor: the Swift client compiled in the same key as
// a literal, and this package existed so the two implementations could not
// drift onto different publishers. The client does not anchor a publisher any
// more -- it verifies a signed SiteID descriptor -- so this is now what its
// name suggests and nothing more: a fixture key for the Go tests, signing the
// demo catalog and nothing else. It is not a release key and nothing outside
// tests should reach for it.
package demotrust

// PublisherKey is the Ed25519 public key, base64, that signs the demo catalog.
const PublisherKey = "SsX0q+oi8C1+v0yTSrltfxYkztmjrdJNE/gN7XN0jEk="
