package gopaque_test

import (
	"github.com/cretz/gopaque/gopaque"
)

// This simple example doesn't marshal the messages, it just sends them.
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

	// Now that we are registered, do an auth. We are using an embedded key
	// exchange here instead of having our own externally which means we have
	// one extra "Finish" step. Note, in other cases we might hold on to the
	// created key exchange so we can get things like the shared secret.
	userAuth := gopaque.NewUserAuth(crypto, []byte("user foo"), gopaque.NewKeyExchangeSigma(crypto))
	serverAuth := gopaque.NewServerAuth(crypto, gopaque.NewKeyExchangeSigma(crypto))
	// Do the auth
	userAuthInit, err := userAuth.Init([]byte("password foo"))
	panicIfErr(err)
	// XXX: Here is where serverRegComplete would be looked up by userAuthInit.UserID.
	serverAuthComplete, err := serverAuth.Complete(userAuthInit, serverRegComplete)
	panicIfErr(err)
	userAuthFinish, userAuthComplete, err := userAuth.Complete(serverAuthComplete)
	panicIfErr(err)
	err = serverAuth.Finish(userAuthComplete)
	panicIfErr(err)

	// Might as well check that the user key is the same as orig
	if !userReg.PrivateKey().Equal(userAuthFinish.UserPrivateKey) {
		panic("Key mismatch")
	}

	// Output:
}
