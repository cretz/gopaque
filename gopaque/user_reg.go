package gopaque

import "go.dedis.ch/kyber"

type UserReg struct {
	crypto  Crypto
	keyPair KeyPair
}

func NewUserReg(crypto Crypto) (u *UserReg, err error) {
	u = &UserReg{crypto: crypto}
	if u.keyPair, err = crypto.GenKeyPair(); err != nil {
		return nil, err
	}
	return u, nil
}

type UserStep1 struct {
	R     kyber.Scalar
	Alpha kyber.Point
}

func (u *UserReg) NewStep1(password []byte) *UserStep1 {
	var s UserStep1
	s.R, s.Alpha = oprfUserStep1(u.crypto, password)
	return s, nil
}

type UserStep2 struct {
}
