package gopaque_test

import (
	"bytes"
	"testing"

	"github.com/cretz/gopaque/gopaque"
)

func TestCryptoAuthEncrypt(t *testing.T) {
	crypto := gopaque.CryptoDefault
	key := crypto.NewKey(nil)
	// Just enc some value then decrypt for now
	plain := []byte("foo")
	encBytes, err := crypto.AuthEncrypt(key, plain)
	assertNoErr(t, err)
	decBytes, err := crypto.AuthDecrypt(key, encBytes)
	assertNoErr(t, err)
	assert(t, bytes.Equal(decBytes, plain), "Mismatch, got %v wanted %v", decBytes, plain)
}
