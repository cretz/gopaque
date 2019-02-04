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
	Alpha  kyber.Point
}

// MarshalBinary implements encoding.BinaryMarshaller.
func (u *UserAuthInit) MarshalBinary() ([]byte, error) {
	b := newBuf(nil)
	b.WriteVarBytes(u.UserID)
	if err := b.WritePoint(u.Alpha); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryMarshaller. The Alpha field must
// be non-nil before calling this. Otherwise, use FromBytes. This can return
// ErrUnmarshalMoreData if the data is too big.
func (u *UserAuthInit) UnmarshalBinary(data []byte) (err error) {
	b := newBuf(data)
	if u.UserID, err = b.ReadVarBytes(); err == nil {
		if err = b.ReadPoint(u.Alpha); err == nil {
			err = b.AssertUnmarshalNoMoreData()
		}
	}
	return
}

// FromBytes populates this from bytes. This can return ErrUnmarshalMoreData if
// the data is too big.
func (u *UserAuthInit) FromBytes(crypto Crypto, data []byte) error {
	u.Alpha = crypto.Point()
	return u.UnmarshalBinary(data)
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
	Key             KeyPair
	ServerPublicKey []byte
}

// Complete takes the server's complete information and decrypts it and returns
// the user auth information.
func (u *UserAuth) Complete(s *ServerAuthComplete) (*UserAuthComplete, error) {
	rwdU := OPRFUserStep3(u.crypto, u.password, u.r, s.V, s.Beta)
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

// ServerAuthComplete is the resulting info from ServerAuth to send back to the
// user. It implements encoding.BinaryMarshaller and
// encoding.BinaryUnmarshaller.
type ServerAuthComplete struct {
	EnvU      []byte
	PublicKey []byte
	V         kyber.Point
	Beta      kyber.Point
}

// MarshalBinary implements encoding.BinaryMarshaller.
func (s *ServerAuthComplete) MarshalBinary() ([]byte, error) {
	b := newBuf(nil)
	b.WriteVarBytes(s.EnvU)
	b.WriteVarBytes(s.PublicKey)
	if err := b.WritePoint(s.V); err != nil {
		return nil, err
	}
	if err := b.WritePoint(s.Beta); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryMarshaller. The V and Beta fields
// must be non-nil before calling this. Otherwise, use FromBytes. This can
// return ErrUnmarshalMoreData if the data is too big.
func (s *ServerAuthComplete) UnmarshalBinary(data []byte) (err error) {
	b := newBuf(data)
	if s.EnvU, err = b.ReadVarBytes(); err == nil {
		if s.PublicKey, err = b.ReadVarBytes(); err == nil {
			if err = b.ReadPoint(s.V); err == nil {
				if err = b.ReadPoint(s.Beta); err == nil {
					err = b.AssertUnmarshalNoMoreData()
				}
			}
		}
	}
	return
}

// FromBytes populates this from bytes. This can return ErrUnmarshalMoreData if
// the data is too big.
func (s *ServerAuthComplete) FromBytes(crypto Crypto, data []byte) error {
	s.V, s.Beta = crypto.Point(), crypto.Point()
	return s.UnmarshalBinary(data)
}

// ServerAuth combines the received UserAuthInit information with the stored
// ServerRegisterComplete information to produce the authentication info to
// give back to the user.
func ServerAuth(crypto Crypto, u *UserAuthInit, s *ServerRegisterComplete) *ServerAuthComplete {
	if !bytes.Equal(u.UserID, s.UserID) {
		panic("Mismatched user IDs")
	}
	complete := &ServerAuthComplete{EnvU: s.EnvU, PublicKey: s.Key.PublicKeyBytes()}
	complete.V, complete.Beta = OPRFServerStep2(crypto, u.Alpha, s.KU)
	return complete
}
