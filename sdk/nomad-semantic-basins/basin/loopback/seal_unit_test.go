package loopback

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func mustSeal(t *testing.T, key, salt []byte, info, direction string, payload []byte) []byte {
	t.Helper()
	sealed, err := seal(key, salt, info, direction, payload)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func mustSalt(t *testing.T) []byte {
	t.Helper()
	salt, err := newSalt()
	if err != nil {
		t.Fatal(err)
	}
	return salt
}

func TestSealRoundTrip(t *testing.T) {
	key := testServiceKey()
	salt := mustSalt(t)
	for _, payload := range [][]byte{
		nil,
		[]byte("x"),
		[]byte(privateQuery),
		bytes.Repeat([]byte{'q'}, paddingBlock),
		bytes.Repeat([]byte{'q'}, paddingBlock*3+7),
	} {
		sealed := mustSeal(t, key, salt, requestInfo, "request", payload)
		opened, err := unseal(key, salt, requestInfo, "request", sealed)
		if err != nil {
			t.Fatalf("%d-byte payload did not open: %v", len(payload), err)
		}
		if !bytes.Equal(opened, payload) && !(len(opened) == 0 && len(payload) == 0) {
			t.Fatalf("%d-byte payload came back as %d bytes", len(payload), len(opened))
		}
	}
}

// Every way of not holding the right key for the right message, in one place.
func TestUnsealFailsClosed(t *testing.T) {
	key := testServiceKey()
	salt := mustSalt(t)
	payload := []byte(privateQuery)
	sealed := mustSeal(t, key, salt, requestInfo, "request", payload)

	otherSalt := mustSalt(t)
	flipped := append([]byte(nil), sealed...)
	flipped[0] ^= 0x01

	cases := map[string]struct {
		key       []byte
		salt      []byte
		info      string
		direction string
		sealed    []byte
	}{
		"another key":         {otherServiceKey(), salt, requestInfo, "request", sealed},
		"another salt":        {key, otherSalt, requestInfo, "request", sealed},
		"the other info":      {key, salt, responseInfo, "request", sealed},
		"the other direction": {key, salt, requestInfo, "response", sealed},
		"a flipped bit":       {key, salt, requestInfo, "request", flipped},
		"truncated":           {key, salt, requestInfo, "request", sealed[:len(sealed)-1]},
		"empty":               {key, salt, requestInfo, "request", nil},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			opened, err := unseal(testCase.key, testCase.salt, testCase.info,
				testCase.direction, testCase.sealed)
			if err == nil {
				t.Fatalf("opened %d bytes that should not have opened", len(opened))
			}
			if !errors.Is(err, ErrUnsealFailed) {
				t.Fatalf("unexpected error kind: %v", err)
			}
			if strings.Contains(err.Error(), name) {
				t.Fatalf("the error names the cause: %v", err)
			}
		})
	}
}

func TestSealedBytesDoNotContainThePayload(t *testing.T) {
	key := testServiceKey()
	salt := mustSalt(t)
	sealed := mustSeal(t, key, salt, requestInfo, "request", []byte(privateQuery))
	if bytes.Contains(sealed, []byte(privateQuery)) {
		t.Fatal("the sealed bytes contain the plaintext")
	}
	for _, word := range strings.Fields(privateQuery) {
		if len(word) >= 6 && bytes.Contains(sealed, []byte(word)) {
			t.Fatalf("the sealed bytes contain %q", word)
		}
	}
	if bytes.Contains(sealed, key) {
		t.Fatal("the sealed bytes contain the service key")
	}
}

// AEAD hides content, not length, and the length of a query is information
// about the query. Padding is what closes that, so it is pinned here rather
// than left to be tuned away later.
func TestSealedLengthRevealsOnlyTheBlock(t *testing.T) {
	key := testServiceKey()
	salt := mustSalt(t)
	sizeOf := func(payload []byte) int {
		return len(mustSeal(t, key, salt, requestInfo, "request", payload))
	}

	short := sizeOf([]byte("a"))
	nearlyFull := sizeOf(bytes.Repeat([]byte{'a'}, paddingBlock-5))
	if short != nearlyFull {
		t.Fatalf("a 1-byte and a %d-byte payload sealed to %d and %d bytes",
			paddingBlock-5, short, nearlyFull)
	}
	next := sizeOf(bytes.Repeat([]byte{'a'}, paddingBlock))
	if next != short+paddingBlock {
		t.Fatalf("crossing a block grew the payload by %d bytes, not %d",
			next-short, paddingBlock)
	}
}

func TestPadUnpadRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 4, paddingBlock - 5, paddingBlock - 4, paddingBlock, paddingBlock + 1} {
		payload := bytes.Repeat([]byte{'p'}, size)
		padded, err := pad(payload)
		if err != nil {
			t.Fatal(err)
		}
		if len(padded)%paddingBlock != 0 {
			t.Fatalf("%d-byte payload padded to %d bytes, not a whole block", size, len(padded))
		}
		if len(padded) < 4+size {
			t.Fatalf("%d-byte payload padded to a shorter %d bytes", size, len(padded))
		}
		opened, err := unpad(padded)
		if err != nil {
			t.Fatal(err)
		}
		if len(opened) != size {
			t.Fatalf("%d-byte payload came back as %d bytes", size, len(opened))
		}
	}
}

func TestUnpadRejectsMalformedPadding(t *testing.T) {
	full, err := pad([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	lying := append([]byte(nil), full...)
	lying[0], lying[1], lying[2], lying[3] = 0xff, 0xff, 0xff, 0xff

	for name, padded := range map[string][]byte{
		"too short":         {0x00, 0x00},
		"not a whole block": full[:len(full)-1],
		"lying length":      lying,
	} {
		t.Run(name, func(t *testing.T) {
			if opened, err := unpad(padded); err == nil {
				t.Fatalf("accepted malformed padding, returning %d bytes", len(opened))
			}
		})
	}
}

func TestSealRejectsUnusableKeysAndSalts(t *testing.T) {
	salt := mustSalt(t)
	if _, err := seal(bytes.Repeat([]byte{1}, MinimumServiceKeyBytes-1), salt,
		requestInfo, "request", []byte("x")); err == nil {
		t.Fatal("sealed under a short key")
	}
	if _, err := seal(testServiceKey(), salt[:saltBytes-1],
		requestInfo, "request", []byte("x")); err == nil {
		t.Fatal("sealed under a short salt")
	}
}

func TestNewSaltIsFresh(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 64; i++ {
		salt := mustSalt(t)
		if len(salt) != saltBytes {
			t.Fatalf("salt is %d bytes, not %d", len(salt), saltBytes)
		}
		if _, repeated := seen[string(salt)]; repeated {
			t.Fatal("newSalt repeated a salt")
		}
		seen[string(salt)] = struct{}{}
	}
}

// The salt and the direction are bound twice: once through the derived key and
// once through the additional data. Each binding is checked on its own here,
// because either one alone is enough to refuse a replayed response, and a test
// that only exercises the pair would let one of them rot unnoticed.
func TestSealedAADBindsLabelDirectionAndSalt(t *testing.T) {
	salt := mustSalt(t)
	other := mustSalt(t)
	request := sealedAAD("request", salt)

	if !bytes.HasPrefix(request, []byte(sealLabel)) {
		t.Fatalf("additional data does not start with the protocol label: %q", request)
	}
	if !bytes.HasSuffix(request, salt) {
		t.Fatal("additional data does not bind the salt")
	}
	if bytes.Equal(request, sealedAAD("response", salt)) {
		t.Fatal("additional data does not separate the two directions")
	}
	if bytes.Equal(request, sealedAAD("request", other)) {
		t.Fatal("additional data is the same under two different salts")
	}
}

// The derived key itself depends on the salt and the direction, independently
// of the additional data above: the ciphertext, not just the tag, must differ.
func TestDerivedKeyDependsOnSaltAndDirection(t *testing.T) {
	key := testServiceKey()
	payload := bytes.Repeat([]byte{'q'}, paddingBlock)
	ciphertext := func(salt []byte, info string) []byte {
		sealed := mustSeal(t, key, salt, info, "request", payload)
		return sealed[:len(sealed)-16]
	}

	first := mustSalt(t)
	second := mustSalt(t)
	if bytes.Equal(ciphertext(first, requestInfo), ciphertext(second, requestInfo)) {
		t.Fatal("two salts produced the same keystream, so the key ignores the salt")
	}
	if bytes.Equal(ciphertext(first, requestInfo), ciphertext(first, responseInfo)) {
		t.Fatal("both directions produced the same keystream, so the key ignores the direction")
	}
}
