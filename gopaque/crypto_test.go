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
	assert(t, !bytes.Equal(decBytes, plain), "Match. A successful decryption occurred\n"+
		"Key 1: %v\n\tEncryption key: %v\n\tDecryption key: %v\nKey 2 :%v\n\tDecryption key: %v",
		keyBytes, authEncKey, authDecKey, keyRandBytes, authDecKey2)
}

func TestCryptoAuthInvalidKey(t *testing.T) {
	crypto := gopaque.CryptoDefault
	encKey := crypto.NewKey(nil)
	decKey := crypto.NewKey(nil)
	plaintext := "Hack the Planet!"
	plain := []byte(plaintext)

	// Encrypt with Key 1
	encBytes, err := crypto.AuthEncrypt(encKey, plain)
	assertNoErr(t, err)

	// Decrypt with Key 2 and confirm it errors
	_, err = crypto.AuthDecrypt(decKey, encBytes)
	assert(t, err != nil && err.Error() == "MAC mismatch", "Expected 'MAC mismatch' error, got: %v", err)
}

func TestCryptoRandomStream(t *testing.T) {
	r1 := gopaque.CryptoDefault.RandomStream()
	r2 := gopaque.CryptoDefault.RandomStream()

	if r1 == r2 {
		t.Errorf("Two random string were the same but should be different: %v:%v", r1, r2)
	}
}

func TestCryptoNewKey(t *testing.T) {
	key1 := gopaque.CryptoDefault.NewKey(gopaque.CryptoDefault.RandomStream())
	key2 := gopaque.CryptoDefault.NewKey(gopaque.CryptoDefault.RandomStream())

	if key1 == key2 {
		t.Errorf("Two input keys created with different inputs yielded the same output but should be different: %v,%v", key1, key2)
	}
}

func TestCryptoDerivedKey(t *testing.T) {
	key1 := gopaque.CryptoDefault.NewKey(gopaque.CryptoDefault.RandomStream())
	encKey1 := gopaque.CryptoDefault.DeriveKey(key1, []byte("encKey"))
	encKey2 := gopaque.CryptoDefault.DeriveKey(key1, []byte("encKey"))

	if encKey1 == encKey2 {
		t.Errorf("Two derived keys created with different inputs yielded the same output but should be different: %v:%v", encKey1, encKey2)
	}
	if encKey1.String() == "af22e0f057b9dccd4b1be5ce77e2e7d557b57970b5267a90f57960924a87f106" {
		t.Errorf("Derived key 1 equals af22e0f057b9dccd4b1be5ce77e2e7d557b57970b5267a90f57960924a87f106")
	}
	if encKey2.String() == "af22e0f057b9dccd4b1be5ce77e2e7d557b57970b5267a90f57960924a87f106" {
		t.Errorf("Derived key 2 equals af22e0f057b9dccd4b1be5ce77e2e7d557b57970b5267a90f57960924a87f106")
	}
}

func TestCryptoDerivedKeyDiscriminator(t *testing.T) {
	key := gopaque.CryptoDefault.NewKey(gopaque.CryptoDefault.RandomStream())
	encKey1 := gopaque.CryptoDefault.DeriveKey(key, []byte("encKey"))
	encKey2 := gopaque.CryptoDefault.DeriveKey(key, []byte("macKey"))

	if encKey1.String() == encKey2.String() {
		t.Errorf("Two derived MAC keys created with different inputs yielded the same output but should be different: %v:%v", encKey1, encKey2)
	}
	if encKey1.String() == "af22e0f057b9dccd4b1be5ce77e2e7d557b57970b5267a90f57960924a87f106" {
		t.Errorf("Derived key 1 equals af22e0f057b9dccd4b1be5ce77e2e7d557b57970b5267a90f57960924a87f106")
	}
	if encKey2.String() == "af22e0f057b9dccd4b1be5ce77e2e7d557b57970b5267a90f57960924a87f106" {
		t.Errorf("Derived key 2 equals af22e0f057b9dccd4b1be5ce77e2e7d557b57970b5267a90f57960924a87f106")
	}
}
