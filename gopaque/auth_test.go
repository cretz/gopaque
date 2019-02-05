package gopaque_test

import (
	"github.com/cretz/gopaque/gopaque"
)

// This simple example doesn't marshal the messages, just sends them back and forth.
func Example_simple() {
	crypto := gopaque.CryptoDefault
	// Registration first...create user side and server side
	userReg := gopaque.NewUserRegister(crypto, []byte("user foo"), nil)
	serverReg := gopaque.NewServerRegister(crypto, crypto.NewKey(nil))
	// Do the registration steps
	userRegInit := userReg.Init([]byte("password foo"))
	serverRegInit := serverReg.Init(userRegInit)
	userRegComplete := userReg.Complete(serverRegInit)
	serverRegComplete := serverReg.Complete(userRegComplete)
	// XXX: Here is where serverRegComplete would be persisted on the server.
	// Now that we are registered, do an auth
	userAuth := gopaque.NewUserAuth(crypto, []byte("user foo"))
	userAuthInit := userAuth.Init([]byte("password foo"))
	// XXX: Here is where serverRegComplete would be looked up by userAuthInit.UserID.
	serverAuthComplete := gopaque.ServerAuth(crypto, userAuthInit, serverRegComplete)
	userAuthComplete, err := userAuth.Complete(serverAuthComplete)
	if err != nil {
		panic(err)
	}
	// XXX: Here is where the user could use its key exchange protocol to verify
	//	    that the server holds the priv for userAuthComplete.ServerPublicKey.
	// XXX: Here is where the server could use its key exchange protocol to verify
	//      that the user holds the priv for serverRegComplete.PubU.

	// Might as well check that the user key is the same as orig
	if !userReg.PrivateKey().Equal(userAuthComplete.UserPrivateKey) {
		panic("Key mismatch")
	}

	// Output:
}
