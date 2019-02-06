package gopaque

import (
	"bytes"
	"crypto/hmac"
	"fmt"

	"go.dedis.ch/kyber"
)

type KeyExchange interface {
	// UserKeyExchange1 runs on the user side and returns the first key exchange
	// value to send to server (or nil if there is none).
	UserKeyExchange1() (Marshaler, error)

	// ServerKeyExchange2 runs on the server side and is given both the result
	// of UserKeyExchange1 (if any) and the server registration info for the
	// user. It returns the value to send back to the user (or nil if there is
	// none).
	ServerKeyExchange2(ke1 Marshaler, info *KeyExchangeInfo) (Marshaler, error)

	// UserKeyExchange3 runs on the user side and is given both the result of
	// ServerKeyExchange2 (if any) and the decoded user info. It returns the
	// value sent back to the server. If the result is nil, this is only a
	// 2-message key exchange instead of a 3-message one and no more steps are
	// done.
	UserKeyExchange3(ke2 Marshaler, info *KeyExchangeInfo) (Marshaler, error)

	// ServerKeyExchange4 runs on the server side and is given the result of
	// UserKeyExchange3. It is not called if there was no result from
	// UserKeyExchange3.
	ServerKeyExchange4(ke3 Marshaler) error

	// NewKeyExchangeMessage just instantiates the message instance for the
	// result of the given step number (1-4).
	NewKeyExchangeMessage(step int) (Marshaler, error)
}

type KeyExchangeInfo struct {
	UserID         []byte
	MyPrivateKey   kyber.Scalar
	TheirPublicKey kyber.Point
}

type KeyExchangeSigma struct {
	crypto Crypto

	myExchangePrivateKey kyber.Scalar
	myExchangePublicKey  kyber.Point
}

type KeyExchangeSigmaMsg1 struct {
	UserExchangePublicKey kyber.Point
}

func (k *KeyExchangeSigmaMsg1) ToBytes() ([]byte, error) {
	b := newBuf(nil)
	err := b.WritePoint(k.UserExchangePublicKey)
	return b.Bytes(), err
}

func (k *KeyExchangeSigmaMsg1) FromBytes(c Crypto, data []byte) (err error) {
	b := newBuf(data)
	k.UserExchangePublicKey, err = b.ReadPoint(c)
	return b.AssertUnmarshalNoMoreDataIfNotErr(err)
}

func (k *KeyExchangeSigma) generateExchangeKeyPair() error {
	if k.myExchangePrivateKey != nil {
		return fmt.Errorf("Private key already set, has this already run?")
	}
	k.myExchangePrivateKey = k.crypto.NewKey(nil)
	k.myExchangePublicKey = pubKey(k.crypto, k.myExchangePrivateKey)
	return nil
}

func (k *KeyExchangeSigma) UserKeyExchange1() (Marshaler, error) {
	if err := k.generateExchangeKeyPair(); err != nil {
		return nil, err
	}
	// KE1: g^x
	return &KeyExchangeSigmaMsg1{UserExchangePublicKey: k.myExchangePublicKey}, nil
}

type KeyExchangeSigmaMsg2 struct {
	ServerExchangePublicKey kyber.Point
	ServerExchangeSig       []byte
	ServerExchangeMac       []byte
}

func (k *KeyExchangeSigmaMsg2) ToBytes() ([]byte, error) {
	b := newBuf(nil)
	err := b.WritePoint(k.ServerExchangePublicKey)
	err = b.WriteVarBytesIfNotErr(err, k.ServerExchangeSig, k.ServerExchangeMac)
	return b.Bytes(), err
}

func (k *KeyExchangeSigmaMsg2) FromBytes(c Crypto, data []byte) (err error) {
	b := newBuf(data)
	k.ServerExchangePublicKey, err = b.ReadPoint(c)
	k.ServerExchangeSig, err = b.ReadVarBytesIfNotErr(err)
	k.ServerExchangeMac, err = b.ReadVarBytesIfNotErr(err)
	return b.AssertUnmarshalNoMoreDataIfNotErr(err)
}

func (k *KeyExchangeSigma) sharedSecret(theirPub kyber.Point) kyber.Point {
	return k.crypto.Point().Mul(k.myExchangePrivateKey, theirPub)
}

func (k *KeyExchangeSigma) macKey(sharedSecret kyber.Point) kyber.Scalar {
	// We create the parent scalar from point then derive
	sharedSecretKey := k.crypto.NewKeyFromReader(bytes.NewReader(toBytes(sharedSecret)))
	return k.crypto.DeriveKey(sharedSecretKey, []byte("sigma-mac"))
}

func (k *KeyExchangeSigma) ServerKeyExchange2(ke1 Marshaler, info *KeyExchangeInfo) (Marshaler, error) {
	if ke1 == nil {
		return nil, fmt.Errorf("Missing ke1")
	} else if err := k.generateExchangeKeyPair(); err != nil {
		return nil, err
	}
	msg1 := ke1.(*KeyExchangeSigmaMsg1)
	// KE2: g^y
	msg2 := &KeyExchangeSigmaMsg2{ServerExchangePublicKey: k.myExchangePublicKey}
	// KE2: Sig(PrivS; g^x, g^y)
	h := k.crypto.Hash()
	h.Write(toBytes(msg1.UserExchangePublicKey))
	h.Write(toBytes(msg2.ServerExchangePublicKey))
	var err error
	if msg2.ServerExchangeSig, err = k.crypto.Sign(info.MyPrivateKey, h.Sum(nil)); err != nil {
		return nil, err
	}
	// KE2: Mac(Km1; IdS)
	// Basically, we need to derive a mac key from the shared secret then sign
	// the server's persistent (i.e. non-exchange) public key with it.
	sharedSecret := k.sharedSecret(msg1.UserExchangePublicKey)
	macKey := k.macKey(sharedSecret)
	h = hmac.New(k.crypto.Hash, toBytes(macKey))
	h.Write(toBytes(pubKey(k.crypto, info.MyPrivateKey)))
	msg2.ServerExchangeMac = h.Sum(nil)
	return msg2, nil
}

func (k *KeyExchangeSigma) NewKeyExchangeMessage(step int) (Marshaler, error) {
	panic("TODO")
}
