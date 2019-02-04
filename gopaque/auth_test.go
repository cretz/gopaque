package gopaque

import (
	"bytes"
	"testing"
)

func TestRegisterAndAuth(t *testing.T) {
	crypto := CryptoDefault
	// Registration first...create user side and server side
	userReg := NewUserRegister(crypto, []byte("user foo"))
	serverReg := NewServerRegister(crypto, crypto.GenerateKey(nil))
	// Do the registration steps
	userRegInit := userReg.Init([]byte("password foo"))
	serverRegInit := serverReg.Init(userRegInit)
	userRegComplete := userReg.Complete(serverRegInit)
	serverRegComplete := serverReg.Complete(userRegComplete)

	// Now that we are registered, do an auth
	userAuth := NewUserAuth(crypto, []byte("user foo"))
	userAuthInit := userAuth.Init([]byte("password foo"))
	serverAuthComplete := ServerAuth(crypto, userAuthInit, serverRegComplete)
	userAuthComplete, err := userAuth.Complete(serverAuthComplete)
	if err != nil {
		t.Fatal(err)
	}

	// Might as well check that the user key is the same as orig
	userRegKey, userAuthKey := userReg.key.ToBytes(), userAuthComplete.Key.ToBytes()
	if !bytes.Equal(userRegKey, userAuthKey) {
		t.Fatal("Key mismatch")
	}
}
