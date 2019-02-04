package gopaque

import (
	"bytes"
	"fmt"

	"go.dedis.ch/kyber"
)

type UserAuth struct {
	crypto   Crypto
	userID   []byte
	password []byte
	r        kyber.Scalar
}

func NewUserAuth(crypto Crypto, userID []byte) *UserAuth {
	return &UserAuth{crypto: crypto, userID: userID}
}

type UserAuthInit struct {
	UserID []byte
	Alpha  kyber.Point
}

func (u *UserAuth) Init(password []byte) *UserAuthInit {
	u.password = password
	init := &UserAuthInit{UserID: u.userID}
	u.r, init.Alpha = oprfUserStep1(u.crypto, password)
	return init
}

type UserAuthComplete struct {
	Key             KeyPair
	ServerPublicKey []byte
}

func (u *UserAuth) Complete(s *ServerAuthComplete) (*UserAuthComplete, error) {
	rwdU := oprfUserStep3(u.crypto, u.password, u.r, s.V, s.Beta)
	decKey := u.crypto.GenerateKey(rwdU)
	var complete UserAuthComplete
	if plain, err := u.crypto.AuthDecrypt(decKey, s.EnvU); err != nil {
		return nil, err
	} else if complete.Key, err = u.crypto.KeyFromBytes(plain); err != nil {
		return nil, err
	} else if complete.ServerPublicKey = plain[complete.Key.BytesSize():]; !bytes.Equal(complete.ServerPublicKey, s.PublicKey) {
		return nil, fmt.Errorf("Server public key mismatch")
	}
	return &complete, nil
}

type ServerAuthComplete struct {
	EnvU      []byte
	PublicKey []byte
	V         kyber.Point
	Beta      kyber.Point
}

func ServerAuth(crypto Crypto, u *UserAuthInit, s *ServerRegisterComplete) *ServerAuthComplete {
	if !bytes.Equal(u.UserID, s.UserID) {
		panic("Mismatched user IDs")
	}
	complete := &ServerAuthComplete{EnvU: s.EnvU, PublicKey: s.Key.PublicKeyBytes()}
	complete.V, complete.Beta = oprfServerStep2(crypto, u.Alpha, s.KU)
	return complete
}
