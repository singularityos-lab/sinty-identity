package jose

import (
	"crypto/ecdsa"
	"strings"
	"testing"
)

func TestSignVerify(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Sign(k, map[string]any{"sub": "alice"})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := k.JWK().Public()
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]*ecdsa.PublicKey{k.ID: pub}
	var c struct{ Sub string }
	if err := Verify(tok, keys, &c); err != nil || c.Sub != "alice" {
		t.Fatalf("valid token refused: %v %q", err, c.Sub)
	}
	parts := strings.Split(tok, ".")
	forged := parts[0] + "." + b64([]byte(`{"sub":"mallory"}`)) + "." + parts[2]
	if Verify(forged, keys, &c) == nil {
		t.Fatal("forged body accepted")
	}
	none := b64([]byte(`{"alg":"none","kid":"`+k.ID+`"}`)) + "." + parts[1] + "."
	if Verify(none, keys, &c) == nil {
		t.Fatal("alg none accepted")
	}
	other, _ := NewKey()
	if Verify(tok, map[string]*ecdsa.PublicKey{k.ID: &other.Private.PublicKey}, &c) == nil {
		t.Fatal("token verified with the wrong key")
	}
}

func TestThumbprintRFC7638Shape(t *testing.T) {
	k, _ := NewKey()
	der, _ := k.Marshal()
	again, err := ParseKey(der)
	if err != nil || again.ID != k.ID || len(k.ID) != 43 {
		t.Fatalf("key round trip: %v %s %s", err, again.ID, k.ID)
	}
}
