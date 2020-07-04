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

func TestDeriveKey(t *testing.T) {
	crypto := gopaque.CryptoDefault
	key := crypto.NewKey(nil)
	//keyBytes := []byte("password") // It will produce and error on key lenght
	// Just enc some value then decrypt for now
	plain := []byte("foo")

	// Derive authEncrypt key from key
	// Key should be at least 32 bytes
	keyBytes, err := key.MarshalBinary()
	assertNoErr(t, err)
	assert(t, len(keyBytes) >= 32, "Key has not sufficient bytes. It has %v", len(keyBytes))

	authEncKey := crypto.NewKeyFromReader(bytes.NewReader(keyBytes))
	encBytes, err := crypto.AuthEncrypt(authEncKey, plain)
	assertNoErr(t, err)

	// Derive authDecrypt key from key
	authDecKey := crypto.NewKeyFromReader(bytes.NewReader(keyBytes))
	decBytes, err := crypto.AuthDecrypt(authDecKey, encBytes)
	assertNoErr(t, err)
	assert(t, bytes.Equal(decBytes, plain), "Mismatch, got %v wanted %v", decBytes, plain)

	// Derive authDecrypt key from a random key
	// It should produce an error while decrypting
	keyRand := crypto.NewKey(nil)
	keyRandBytes, err := keyRand.MarshalBinary()
	assertNoErr(t, err)
	assert(t, len(keyRandBytes) >= 32, "Key has not sufficient bytes. It has %v", len(keyRandBytes))

	authDecKey2 := crypto.NewKeyFromReader(bytes.NewReader(keyRandBytes))
	decBytes, err = crypto.AuthDecrypt(authDecKey2, encBytes)
	assert(t, false == bytes.Equal(decBytes, plain),
		"Match. A successful decryption occurred\nKey 1: %v\n\tEncryption key: %v\n\tDecryption key: %v\nKey 2 :%v\n\tDecryption key: %v", keyBytes, authEncKey, authDecKey, keyRandBytes, authDecKey2)
}
