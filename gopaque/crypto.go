package gopaque

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"

	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/suites"
	"go.dedis.ch/kyber/util/random"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
)

type Crypto interface {
	suites.Suite

	HashToPoint(msg []byte) kyber.Point
	// Byte slice may be longer than needed, use BytesSize() to see what may be left
	KeyFromBytes(key []byte) (KeyPair, error)
	// Empty seed means crypto/rand
	GenerateKey(seed []byte) KeyPair
	AuthEncrypt(key KeyPair, plain []byte) ([]byte, error)
	AuthDecrypt(key KeyPair, enc []byte) ([]byte, error)
}

var CryptoDefault Crypto = Ed25519CryptoDefault

type KeyPair interface {
	PublicKeyBytes() []byte
	PrivateKeyBytes() []byte
	ToBytes() []byte
	BytesSize() int
}

type Ed25519Crypto struct {
	// Required. Hash should never be smaller than 32 (the gen key seed size)
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
	if len(key) < ed25519.PrivateKeySize {
		return nil, fmt.Errorf("Expected at least %v bytes in key", ed25519.PrivateKeySize)
	}
	return Ed25519KeyPair(key[:ed25519.PrivateKeySize]), nil
}

func (e *Ed25519Crypto) GenerateKey(seed []byte) KeyPair {
	// If seed size is smaller than required, hash to get better size
	if len(seed) > 0 && len(seed) < ed25519.SeedSize {
		seedH := e.Hash()
		if seedH.Size() < ed25519.SeedSize {
			panic("Hash size < needed seed size")
		}
		seedH.Write(seed)
		seed = seedH.Sum(nil)
	}
	var randR io.Reader
	if len(seed) > 0 {
		randR = bytes.NewReader(seed)
	}
	_, priv, err := ed25519.GenerateKey(randR)
	if err != nil {
		panic(err)
	}
	return Ed25519KeyPair(priv)
}

func (e *Ed25519Crypto) AuthEncrypt(key KeyPair, plain []byte) ([]byte, error) {
	// TODO: can an alternative be nacl secretbox instead?
	// We need two deterministic keys for the parent key, one for AES and one for MAC
	edKey := key.(Ed25519KeyPair)
	encKey, macKey := e.DeriveKey(edKey, []byte("encKey")), e.DeriveKey(edKey, []byte("macKey"))
	// Encrypt first
	encBytes, err := e.aesCBCEncrypt(encKey, plain)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(e.Hash, macKey)
	mac.Write(encBytes)
	macBytes := mac.Sum(nil)
	// Just put the MAC at the end
	return append(encBytes, macBytes...), nil
}

func (e *Ed25519Crypto) aesCBCEncrypt(key Ed25519KeyPair, plain []byte) ([]byte, error) {
	// We need to pad w/ repeated bytes of pad amount, and if none are needed we do a whole block of it
	padAmount := byte(aes.BlockSize - (len(plain) % aes.BlockSize))
	if padAmount == 0 {
		padAmount = aes.BlockSize
	}
	padded := make([]byte, len(plain)+int(padAmount))
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = padAmount
	}
	// Just use the first 32 bytes for the key
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	// Includes IV
	enc := make([]byte, aes.BlockSize+len(padded))
	random.Bytes(enc[:aes.BlockSize], e.RandomStream())
	mode := cipher.NewCBCEncrypter(block, enc[:aes.BlockSize])
	mode.CryptBlocks(enc[aes.BlockSize:], padded)
	return enc, nil

}

func (e *Ed25519Crypto) AuthDecrypt(key KeyPair, enc []byte) ([]byte, error) {
	// Build the same two keys for AES and MAC
	edKey := key.(Ed25519KeyPair)
	encKey, macKey := e.DeriveKey(edKey, []byte("encKey")), e.DeriveKey(edKey, []byte("macKey"))
	macSize := e.Hash().Size()
	encBytes, macBytes := enc[:len(enc)-macSize], enc[len(enc)-macSize:]
	// First check the mac
	mac := hmac.New(e.Hash, macKey)
	mac.Write(encBytes)
	if !hmac.Equal(mac.Sum(nil), macBytes) {
		return nil, fmt.Errorf("MAC mismatch")
	}
	// Now just decrypt
	return e.aesCBCDecrypt(encKey, encBytes)
}

func (e *Ed25519Crypto) aesCBCDecrypt(key Ed25519KeyPair, enc []byte) ([]byte, error) {
	// IV is first block
	if len(enc) < aes.BlockSize || len(enc)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("Invalid enc size")
	}
	// Just use the first 32 bytes for the key
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	decPadded := make([]byte, len(enc[aes.BlockSize:]))
	mode := cipher.NewCBCDecrypter(block, enc[:aes.BlockSize])
	mode.CryptBlocks(decPadded, enc[aes.BlockSize:])
	// Validate it is padded with the bytes representing the pad amount
	padAmount := decPadded[len(decPadded)-1]
	if padAmount == 0 || padAmount > aes.BlockSize {
		return nil, fmt.Errorf("Pad validation fail")
	}
	for i := 1; i <= int(padAmount); i++ {
		if decPadded[len(decPadded)-i] != padAmount {
			return nil, fmt.Errorf("Pad validation fail")
		}
	}
	return decPadded[:len(decPadded)-int(padAmount)], nil
}

func (e *Ed25519Crypto) DeriveKey(key Ed25519KeyPair, info []byte) Ed25519KeyPair {
	d := e.Ed25519KeyDeriver
	if d == nil {
		d = Ed25519KeyDeriverDefault
	}
	return d.DeriveKey(key, info)
}

// Just the priv key
type Ed25519KeyPair []byte

func (e Ed25519KeyPair) PublicKeyBytes() []byte {
	return ed25519.PrivateKey(e).Public().(ed25519.PublicKey)
}
func (e Ed25519KeyPair) PrivateKeyBytes() []byte { return e }
func (e Ed25519KeyPair) ToBytes() []byte         { return e }
func (e Ed25519KeyPair) BytesSize() int          { return len(e) }

type Ed25519KeyDeriver interface {
	DeriveKey(key Ed25519KeyPair, info []byte) Ed25519KeyPair
}

var Ed25519KeyDeriverDefault Ed25519KeyDeriver = &Ed25519KeyDeriverHKDF{}

type Ed25519KeyDeriverHKDF struct {
	// Nil uses SHA-256
	NewHash func() hash.Hash
}

func (e *Ed25519KeyDeriverHKDF) DeriveKey(key Ed25519KeyPair, info []byte) Ed25519KeyPair {
	newHash := e.NewHash
	if newHash == nil {
		newHash = sha256.New
	}
	hkdfR := hkdf.New(newHash, key.PrivateKeyBytes(), nil, info)
	_, priv, err := ed25519.GenerateKey(hkdfR)
	if err != nil {
		panic(err)
	}
	return Ed25519KeyPair(priv)
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

func (e *Ed25519KeyDeriverArgon) DeriveKey(key Ed25519KeyPair, info []byte) Ed25519KeyPair {
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
	_, priv, err := ed25519.GenerateKey(bytes.NewReader(argonHash))
	if err != nil {
		panic(err)
	}
	return Ed25519KeyPair(priv)
}
