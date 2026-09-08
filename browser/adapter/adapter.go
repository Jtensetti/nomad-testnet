package adapter

import (
	"errors"
	"strings"

	"github.com/Jtensetti/nomad-browser/localcache"
)

type Request struct {
	Method string
	Path   string
}

type Response struct {
	Status    int
	MediaType string
	Headers   map[string]string
	Body      []byte
}

type Adapter struct {
	store  localcache.Reader
	bundle *Bundle
}

func New(store localcache.Reader, bundleID [32]byte) (*Adapter, error) {
	if store == nil {
		return nil, errors.New("verified local store is required")
	}
	object, err := store.Get(bundleID)
	if err != nil {
		return nil, err
	}
	bundle, err := ParseBundle(object.Bytes)
	if err != nil {
		return nil, err
	}
	return &Adapter{store: store, bundle: bundle}, nil
}

// Handle resolves a renderer request entirely from verified local objects. It
// has no URL resolver, DNS hook, HTTP client, socket or network fallback.
func (a *Adapter) Handle(request Request) (Response, error) {
	if a == nil || a.store == nil || a.bundle == nil {
		return Response{}, errors.New("adapter is not initialized")
	}
	method := strings.ToUpper(request.Method)
	if method != "GET" && method != "HEAD" {
		return Response{Status: 405, Headers: securityHeaders()}, nil
	}
	if err := validateResourcePath(request.Path); err != nil {
		return Response{Status: 400, Headers: securityHeaders()}, nil
	}
	entry, ok := a.bundle.Entry(request.Path)
	if !ok {
		return Response{Status: 404, Headers: securityHeaders()}, nil
	}
	object, err := a.store.Get(entry.ObjectID)
	if err != nil {
		if errors.Is(err, localcache.ErrNotFound) {
			return Response{Status: 404, Headers: securityHeaders()}, nil
		}
		return Response{}, err
	}
	response := Response{
		Status:    200,
		MediaType: entry.MediaType,
		Headers:   securityHeaders(),
	}
	if method == "GET" {
		response.Body = append([]byte(nil), object.Bytes...)
	}
	return response, nil
}

func securityHeaders() map[string]string {
	return map[string]string{
		"Content-Security-Policy": "default-src 'none'; base-uri 'none'; connect-src 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
		"Permissions-Policy":      "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
	}
}
