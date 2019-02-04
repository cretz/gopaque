package gopaque_test

import (
	"bytes"

	"github.com/cretz/gopaque/gopaque"
)

// This simple example doesn't marshal the messages, just sends them back and forth.
func Example_simple() {
	crypto := gopaque.CryptoDefault
	// Registration first...create user side and server side
	userReg := gopaque.NewUserRegister(crypto, []byte("user foo"), nil)
	serverReg := gopaque.NewServerRegister(crypto, crypto.GenerateKey(nil))
	// Do the registration steps
	userRegInit := userReg.Init([]byte("password foo"))
	serverRegInit := serverReg.Init(userRegInit)
	userRegComplete := userReg.Complete(serverRegInit)
	serverRegComplete := serverReg.Complete(userRegComplete)

	// Now that we are registered, do an auth
	userAuth := gopaque.NewUserAuth(crypto, []byte("user foo"))
	userAuthInit := userAuth.Init([]byte("password foo"))
	serverAuthComplete := gopaque.ServerAuth(crypto, userAuthInit, serverRegComplete)
	userAuthComplete, err := userAuth.Complete(serverAuthComplete)
	if err != nil {
		panic(err)
	}

	// Might as well check that the user key is the same as orig
	userRegKey, userAuthKey := userReg.Key().ToBytes(), userAuthComplete.Key.ToBytes()
	if !bytes.Equal(userRegKey, userAuthKey) {
		panic("Key mismatch")
	}

	// Output:
}
