package egress

import (
	"errors"
	"fmt"
	"mime"
	"net/url"
	"sort"
	"strings"
)

type Capability string

const (
	DNS                 Capability = "dns"
	TCP                 Capability = "tcp"
	UDP                 Capability = "udp"
	HTTP                Capability = "http"
	WebSocket           Capability = "websocket"
	WebRTC              Capability = "webrtc"
	Preconnect          Capability = "preconnect"
	SpeculativeFetch    Capability = "speculative-fetch"
	ServiceWorkerUpdate Capability = "service-worker-update"
	ExtensionNetwork    Capability = "extension-network"
	Telemetry           Capability = "telemetry"
	CrashReporting      Capability = "crash-reporting"
	SafeBrowsing        Capability = "safe-browsing"
)

var forbidden = []Capability{
	DNS,
	TCP,
	UDP,
	HTTP,
	WebSocket,
	WebRTC,
	Preconnect,
	SpeculativeFetch,
	ServiceWorkerUpdate,
	ExtensionNetwork,
	Telemetry,
	CrashReporting,
	SafeBrowsing,
}

var ErrDenied = errors.New("browser network egress denied")

// Policy is intentionally not configurable: Nomad renderer contexts deny every
// network capability. Engine adapters may expose only local verified-resource
// reads outside this type.
type Policy struct{}

func (Policy) Authorize(capability Capability) error {
	for _, denied := range forbidden {
		if capability == denied {
			return fmt.Errorf("%w: %s", ErrDenied, capability)
		}
	}
	return fmt.Errorf("%w: unknown capability %q", ErrDenied, capability)
}

func ForbiddenCapabilities() []Capability {
	return append([]Capability(nil), forbidden...)
}

// CheckRendererURL allows only non-network renderer-local schemes. A real
// Firefox/Chromium integration must call this before scheme dispatch and must
// also route all lower-level capabilities through Authorize.
func (Policy) CheckRendererURL(raw string) error {
	if len(raw) > MaxResourcePath {
		return fmt.Errorf("%w: URL is too long", ErrDenied)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: malformed URL", ErrDenied)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "nomad":
		if parsed.User != nil || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("%w: invalid local Nomad URL", ErrDenied)
		}
		// The same rule the local adapter applies, so a URL this gate admits
		// is one the adapter will resolve, and neither gate is the lenient
		// one. Percent-encoded traversal decodes into Path before this runs.
		if err := CanonicalResourcePath(parsed.Path); err != nil {
			return fmt.Errorf("%w: %v", ErrDenied, err)
		}
		return nil
	case "data":
		return checkDataURL(parsed.Opaque)
	case "about":
		if raw == "about:blank" {
			return nil
		}
	}
	return fmt.Errorf("%w: scheme %q", ErrDenied, parsed.Scheme)
}

// dataMediaTypes are the media types a data: URL may carry.
//
// The list is an allowlist of non-scriptable types rather than a denylist of
// scriptable ones. A directly navigated data: URL is its own document with an
// opaque origin: it does not inherit the Content-Security-Policy the local
// adapter attaches to its responses, so "default-src 'none'" does not reach
// it and script inside it runs unconstrained by that header. What actually
// stops such a script from reaching the network is the release binary having
// no network entitlement at all -- but a URL policy that admits scriptable
// documents is not the control it claims to be, and leaving the whole
// guarantee resting on the entitlement gives up defence in depth for nothing.
var dataMediaTypes = map[string]struct{}{
	"text/plain":      {},
	"text/css":        {},
	"image/png":       {},
	"image/jpeg":      {},
	"image/gif":       {},
	"image/webp":      {},
	"image/avif":      {},
	"font/woff":       {},
	"font/woff2":      {},
	"font/ttf":        {},
	"font/otf":        {},
	"application/pdf": {},
}

// AllowedDataMediaTypes lists what a data: URL may carry.
func AllowedDataMediaTypes() []string {
	allowed := make([]string, 0, len(dataMediaTypes))
	for mediaType := range dataMediaTypes {
		allowed = append(allowed, mediaType)
	}
	sort.Strings(allowed)
	return allowed
}

func checkDataURL(opaque string) error {
	// A data: URL with no media type defaults to text/plain, which is
	// allowed, but an empty payload is malformed rather than empty text.
	comma := strings.IndexByte(opaque, ',')
	if comma < 0 {
		return fmt.Errorf("%w: malformed data URL", ErrDenied)
	}
	header := opaque[:comma]
	header = strings.TrimSuffix(header, ";base64")
	if header == "" {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(header)
	if err != nil {
		return fmt.Errorf("%w: unparsable data URL media type", ErrDenied)
	}
	if _, allowed := dataMediaTypes[strings.ToLower(mediaType)]; !allowed {
		return fmt.Errorf("%w: data URL media type %q is not in the non-scriptable allowlist",
			ErrDenied, mediaType)
	}
	return nil
}
