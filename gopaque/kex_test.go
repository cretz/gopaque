package gopaque_test

import (
	"testing"

	"github.com/cretz/gopaque/gopaque"
)

func TestKeyExchangeSigma(t *testing.T) {
	crypto := gopaque.CryptoDefault
	// Create external info
	userID := []byte("some user")
	userPriv, serverPriv := crypto.NewKey(nil), crypto.NewKey(nil)
	userPub, serverPub := pubKey(crypto, userPriv), pubKey(crypto, serverPriv)
	// Do the exchange
	userKex, serverKex := gopaque.NewKeyExchangeSigma(crypto), gopaque.NewKeyExchangeSigma(crypto)
	ke1, err := userKex.UserKeyExchange1()
	assertNoErr(t, err)
	ke2, err := serverKex.ServerKeyExchange2(ke1, &gopaque.KeyExchangeInfo{
		UserID:         userID,
		MyPrivateKey:   serverPriv,
		TheirPublicKey: userPub,
	})
	assertNoErr(t, err)
	ke3, err := userKex.UserKeyExchange3(ke2, &gopaque.KeyExchangeInfo{
		UserID:         userID,
		MyPrivateKey:   userPriv,
		TheirPublicKey: serverPub,
	})
	assertNoErr(t, err)
	err = serverKex.ServerKeyExchange4(ke3)
	// Check
	assert(t, userKex.SharedSecret.Equal(serverKex.SharedSecret), "Shared secret mismatch")
}
