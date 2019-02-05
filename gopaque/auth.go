package gopaque

import (
	"bytes"
	"fmt"

	"go.dedis.ch/kyber"
)

// UserAuth is the user-side authentication session for a registered user. The
// Init step gives a message that can be sent to the server and the response can
// be given to Complete to complete the authentication. Both the message sent
// from Init and received from the server are often interspersed in an existing
// key exchange. This should be created each auth attempt and never reused.
type UserAuth struct {
	crypto   Crypto
	userID   []byte
	password []byte
	r        kyber.Scalar
}

// NewUserAuth creates a new auth session for the given userID.
func NewUserAuth(crypto Crypto, userID []byte) *UserAuth {
	return &UserAuth{crypto: crypto, userID: userID}
}

// UserAuthInit is the set of data to pass to the server after calling
// UserAuth.Init. It implements encoding.BinaryMarshaller and
// encoding.BinaryUnmarshaller.
type UserAuthInit struct {
	UserID []byte

	Alpha kyber.Point
}

// ToBytes implements Marshaler.ToBytes.
func (u *UserAuthInit) ToBytes() ([]byte, error) {
	b := newBuf(nil)
	b.WriteVarBytes(u.UserID)
	err := b.WritePoint(u.Alpha)
	return b.Bytes(), err
}

// FromBytes implements Marshaler.FromBytes. This can return
// ErrUnmarshalMoreData if the data is too big.
func (u *UserAuthInit) FromBytes(c Crypto, data []byte) (err error) {
	b := newBuf(data)
	u.UserID, err = b.ReadVarBytes()
	u.Alpha, err = b.ReadPointIfNotErr(c, err)
	return b.AssertUnmarshalNoMoreDataIfNotErr(err)
}

// Init creates the first set of data to send to the server from the given
// password.
func (u *UserAuth) Init(password []byte) *UserAuthInit {
	u.password = password
	init := &UserAuthInit{UserID: u.userID}
	u.r, init.Alpha = OPRFUserStep1(u.crypto, password)
	return init
}

// UserAuthComplete is the completed information for use once auth is done.
type UserAuthComplete struct {
	UserPrivateKey  kyber.Scalar
	ServerPublicKey kyber.Point
}

// Complete takes the server's complete information and decrypts it and returns
// the user auth information.
//
// Note, this doesn't completely validate the server. Callers are expected to,
// using their external key exchange protocol, prove that the server holds the
// private key for the resulting UserAuthComplete.ServerPublicKey.
func (u *UserAuth) Complete(s *ServerAuthComplete) (*UserAuthComplete, error) {
	rwdU := OPRFUserStep3(u.crypto, u.password, u.r, s.V, s.Beta)
	decKey := u.crypto.NewKeyFromReader(bytes.NewReader(rwdU))
	complete := &UserAuthComplete{UserPrivateKey: u.crypto.Scalar(), ServerPublicKey: u.crypto.Point()}
	privKeyLen := u.crypto.ScalarLen()
	if plain, err := u.crypto.AuthDecrypt(decKey, s.EnvU); err != nil {
		return nil, err
	} else if err = complete.UserPrivateKey.UnmarshalBinary(plain[:privKeyLen]); err != nil {
		return nil, err
	} else if err = complete.ServerPublicKey.UnmarshalBinary(plain[privKeyLen:]); err != nil {
		return nil, err
	} else if !complete.ServerPublicKey.Equal(s.ServerPublicKey) {
		return nil, fmt.Errorf("Server public key mismatch")
	}
	return complete, nil
}

// ServerAuthComplete is the resulting info from ServerAuth to send back to the
// user. It implements encoding.BinaryMarshaller and
// encoding.BinaryUnmarshaller.
type ServerAuthComplete struct {
	ServerPublicKey kyber.Point

	EnvU []byte
	V    kyber.Point
	Beta kyber.Point
}

// ToBytes implements Marshaler.ToBytes.
func (s *ServerAuthComplete) ToBytes() ([]byte, error) {
	b := newBuf(nil)
	err := b.WritePoint(s.ServerPublicKey)
	err = b.WriteVarBytesIfNotErr(err, s.EnvU)
	err = b.WritePointIfNotErr(err, s.V, s.Beta)
	return b.Bytes(), err
}

// FromBytes implements Marshaler.FromBytes. This can return
// ErrUnmarshalMoreData if the data is too big.
func (s *ServerAuthComplete) FromBytes(c Crypto, data []byte) (err error) {
	b := newBuf(data)
	s.ServerPublicKey, err = b.ReadPoint(c)
	s.EnvU, err = b.ReadVarBytesIfNotErr(err)
	s.V, err = b.ReadPointIfNotErr(c, err)
	s.Beta, err = b.ReadPointIfNotErr(c, err)
	return b.AssertUnmarshalNoMoreDataIfNotErr(err)
}

// ServerAuth combines the received UserAuthInit information with the stored
// ServerRegisterComplete information to produce the authentication info to
// give back to the user.
//
// Note, this does not completely validate the user. Callers are expected, in
// their external key exchange protocol, to prove the user holds the private key
// for ServerRegisterComplete.PubU.
func ServerAuth(crypto Crypto, u *UserAuthInit, s *ServerRegisterComplete) *ServerAuthComplete {
	if !bytes.Equal(u.UserID, s.UserID) {
		panic("Mismatched user IDs")
	}
	complete := &ServerAuthComplete{ServerPublicKey: crypto.Point().Mul(s.ServerPrivateKey, nil), EnvU: s.EnvU}
	complete.V, complete.Beta = OPRFServerStep2(crypto, u.Alpha, s.KU)
	return complete
}
