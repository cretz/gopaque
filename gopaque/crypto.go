package gopaque

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/suites"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
)

type Crypto interface {
	suites.Suite

	HashToPoint(msg []byte) kyber.Point
	KeyFromBytes(key []byte) (KeyPair, error)
	GenerateKey() KeyPair
	AuthEncrypt(key KeyPair, plain []byte) ([]byte, error)
	AuthDecrypt(key KeyPair, enc []byte) ([]byte, error)
}

var CryptoDefault Crypto = Ed25519CryptoDefault

type KeyPair interface {
	PublicKeyBytes() []byte
	PrivateKeyBytes() []byte
	ToBytes() []byte
}

type Ed25519Crypto struct {
	// Required
	suites.Suite
	// If nil, uses Ed25519KeyDeriverDefault
	Ed25519KeyDeriver
}

var Ed25519CryptoDefault = &Ed25519Crypto{Suite: suites.MustFind("Ed25519")}

func (e *Ed25519Crypto) HashToPoint(msg []byte) kyber.Point {
	// TODO: Since functionality was removed in https://github.com/dedis/kyber/pull/352, we just copied the BLS
	// code but we need to reintroduce proper elligator or something when it's back.
	h := e.Hash()
	h.Write(msg)
	x := e.Scalar().SetBytes(h.Sum(nil))
	return e.Point().Mul(x, nil)
}

func (e *Ed25519Crypto) KeyFromBytes(key []byte) (KeyPair, error) {
	if exp := ed25519.PublicKeySize + ed25519.PrivateKeySize; len(key) != exp {
		return nil, fmt.Errorf("Expected %v bytes", exp)
	}
	return &Ed25519KeyPair{key[:ed25519.PublicKeySize], key[ed25519.PublicKeySize:]}, nil
}

func (e *Ed25519Crypto) GenerateKey() KeyPair {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return &Ed25519KeyPair{pub, priv}
}

func (e *Ed25519Crypto) AuthEncrypt(key KeyPair, plain []byte) ([]byte, error) {
	panic("TODO")
}

func (e *Ed25519Crypto) AuthDecrypt(key KeyPair, env []byte) ([]byte, error) {
	panic("TODO")
}

type Ed25519KeyPair struct {
	// XXX: I could use something like https://godoc.org/github.com/cretz/bine/torutil/ed25519 and regen the pub
	// key on demand.
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func (e *Ed25519KeyPair) PublicKeyBytes() []byte  { return e.PublicKey }
func (e *Ed25519KeyPair) PrivateKeyBytes() []byte { return e.PrivateKey }
func (e *Ed25519KeyPair) ToBytes() []byte {
	b := make([]byte, ed25519.PublicKeySize+ed25519.PrivateKeySize)
	copy(b, e.PublicKey)
	copy(b[:ed25519.PublicKeySize], e.PrivateKey)
	return b
}

type Ed25519KeyDeriver interface {
	DeriveKey(key *Ed25519KeyPair, info []byte) *Ed25519KeyPair
}

var Ed25519KeyDeriverDefault Ed25519KeyDeriver = &Ed25519KeyDeriverHKDF{}

type Ed25519KeyDeriverHKDF struct {
	// Nil uses SHA-256
	NewHash func() hash.Hash
}

func (e *Ed25519KeyDeriverHKDF) DeriveKey(key *Ed25519KeyPair, info []byte) *Ed25519KeyPair {
	newHash := e.NewHash
	if newHash == nil {
		newHash = sha256.New
	}
	hkdfR := hkdf.New(newHash, key.PrivateKeyBytes(), nil, info)
	pub, priv, err := ed25519.GenerateKey(hkdfR)
	if err != nil {
		panic(err)
	}
	return &Ed25519KeyPair{pub, priv}
}

type Ed25519KeyDeriverArgon struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	// Nil uses SHA-512
	NewHash func() hash.Hash
}

var Ed25519KeyDeriverArgonDefault = &Ed25519KeyDeriverArgon{
	Time:    1,
	Memory:  64 * 1024,
	Threads: 4,
}
var _ Ed25519KeyDeriver = Ed25519KeyDeriverArgonDefault

func (e *Ed25519KeyDeriverArgon) DeriveKey(key *Ed25519KeyPair, info []byte) *Ed25519KeyPair {
	// Build a 32-byte argon2 hash with the private part of the master key as the password, the SHA-512 (or other) name
	// as the salt, and the other argon params as given. Then use that 32-byte hash as the input for an ed25519 key.
	// I.e. ed25519-gen(argon2(P=master, S=sha512(name), ...))
	// Hash the info bytes
	infoNewHash := e.NewHash
	if infoNewHash == nil {
		infoNewHash = sha512.New
	}
	infoHasher := infoNewHash()
	infoHasher.Write(info)
	infoHash := infoHasher.Sum(nil)
	argonHash := argon2.IDKey(key.PrivateKeyBytes(), infoHash, e.Time, e.Memory, e.Threads, 32)
	// Based on reading, only reason this returns an err is if random does which it shouldn't
	pub, priv, err := ed25519.GenerateKey(bytes.NewReader(argonHash))
	if err != nil {
		panic(err)
	}
	return &Ed25519KeyPair{pub, priv}
}
