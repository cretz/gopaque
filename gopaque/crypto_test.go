package gopaque_test

import (
	"bytes"
	"testing"

	"github.com/cretz/gopaque/gopaque"
)

func TestEd25519CryptoAuthEncrypt(t *testing.T) {
	crypto := gopaque.Ed25519CryptoDefault
	key := crypto.GenerateKey(nil)
	// Just enc some value then decrypt for now
	plain := []byte("foo")
	if encBytes, err := crypto.AuthEncrypt(key, plain); err != nil {
		t.Fatal(err)
	} else if decBytes, err := crypto.AuthDecrypt(key, encBytes); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(decBytes, plain) {
		t.Fatalf("Mismatch, got %v wanted %v", decBytes, plain)
	}
}
