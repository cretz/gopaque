package gopaque

import (
	"go.dedis.ch/kyber"
)

type ServerReg struct {
	crypto  Crypto
	keyPair KeyPair

	kU kyber.Scalar
}

func NewServerReg(crypto Crypto, keyPair KeyPair) *ServerReg {
	return &ServerReg{
		crypto:  crypto,
		keyPair: keyPair,
		kU:      crypto.Scalar().Pick(crypto.RandomStream()),
	}
}

type ServerStep1 struct {
	PublicKey []byte
	Beta      kyber.Point
}

func (s *ServerReg) NewStep1(u *UserStep1) *ServerStep1 {
	return &ServerStep1{
		PublicKey: s.keyPair.PublicKey(),
		Beta:      oprfServerStep2(u.Alpha, s.kU),
	}
}
