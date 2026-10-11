// Command nomad-embed-service is the shim that stands between a Nomad client
// and a local model server.
//
// It is the only process in a deployment that sees a reader's query in the
// clear, and it holds the key that entitles it to. Everything it refuses, it
// refuses closed: there is no mode in which it serves an unauthenticated
// request, and no mode in which it forwards a query anywhere but loopback.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Jtensetti/nomad-semantic-basins/basin/loopback"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8779", "loopback address to serve on")
	upstream := flag.String("upstream", "http://127.0.0.1:8080", "local model server base URL")
	keyFile := flag.String("key-file", "", "file holding the shared service key")
	generate := flag.Bool("generate-key", false, "write a new service key to -key-file and exit")
	upstreamKeyFile := flag.String("upstream-key-file", "",
		"optional file holding the model server's own API key")
	timeout := flag.Duration("upstream-timeout", 10*time.Second, "model server timeout")
	flag.Parse()

	if *keyFile == "" {
		log.Fatal("-key-file is required; the service key is never passed on the command line, "+
			"where every process on the host can read it from ", "the process table")
	}
	if *generate {
		if err := generateKey(*keyFile); err != nil {
			log.Fatal(err)
		}
		log.Printf("wrote a new service key to %s; give the same bytes to the client", *keyFile)
		return
	}

	serviceKey, err := readKeyFile(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	upstreamKey := ""
	if *upstreamKeyFile != "" {
		raw, err := readKeyFile(*upstreamKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		upstreamKey = string(raw)
	}
	if err := checkListenAddress(*listen); err != nil {
		log.Fatal(err)
	}

	service := loopback.Service{
		ServiceKey: serviceKey,
		Upstream: loopback.OpenAIUpstream{
			BaseURL: *upstream,
			APIKey:  upstreamKey,
			Timeout: *timeout,
		},
	}
	server := &http.Server{
		Addr:              *listen,
		Handler:           service,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("serving sealed embedding requests on http://%s%s", *listen, loopback.SealedPath)
	log.Fatal(server.ListenAndServe())
}

// checkListenAddress refuses any address that would expose the shim off the
// host. The client will only talk to loopback, so a non-loopback listener
// could serve no legitimate client and every illegitimate one.
func checkListenAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("-listen must be host:port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("-listen must be a literal loopback IP; the embedding service " +
			"must not be reachable from off the host")
	}
	return nil
}

func generateKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite a service key, because "+
			"every client still holding the old one would silently stop working", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	key, err := loopback.NewServiceKey()
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(encodeKey(key)), 0o600)
}

func encodeKey(key []byte) string {
	encoded := make([]byte, 0, len(key)*2+1)
	const digits = "0123456789abcdef"
	for _, b := range key {
		encoded = append(encoded, digits[b>>4], digits[b&0x0f])
	}
	return string(encoded) + "\n"
}

// readKeyFile reads a key and refuses one any other account can read.
//
// A key file readable by another user is a key that other user holds, and the
// whole point of this key is that exactly two processes hold it.
func readKeyFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is mode %04o; a service key must not be readable by "+
			"any other account, so make it 0600", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeKey(strings.TrimSpace(string(raw)))
}

func decodeKey(text string) ([]byte, error) {
	if text == "" {
		return nil, errors.New("the key file is empty")
	}
	key := make([]byte, 0, len(text)/2)
	if len(text)%2 == 0 && isHex(text) {
		for index := 0; index < len(text); index += 2 {
			var value int
			if _, err := fmt.Sscanf(text[index:index+2], "%02x", &value); err != nil {
				return nil, err
			}
			key = append(key, byte(value))
		}
	} else {
		key = []byte(text)
	}
	if len(key) < loopback.MinimumServiceKeyBytes {
		return nil, fmt.Errorf("the service key is %d bytes; at least %d are required",
			len(key), loopback.MinimumServiceKeyBytes)
	}
	return key, nil
}

func isHex(text string) bool {
	for _, r := range text {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}
