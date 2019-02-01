package gopaque

import (
	"go.dedis.ch/kyber/suites"
)

type Crypto interface {
	suites.Suite

	GenKeyPair() (KeyPair, error)
	AuthEncrypt(key []byte, userKeyPair KeyPair, serverKey []byte) ([]byte, error)
}

type KeyPair interface {
	PublicKey []byte
}
