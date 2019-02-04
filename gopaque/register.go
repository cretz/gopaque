package gopaque

import (
	"go.dedis.ch/kyber"
)

// UserRegister is the user-side session for registration with a server. This
// should be created for each server registration and never reused. Once
// created via NewUserRegister, Init can be called with a password that will
// return a value that can be sent to the server. The value that the server
// returns can then be used for Complete. The resulting value from Complete is
// then passed back to the server to complete registration.
type UserRegister struct {
	crypto   Crypto
	userID   []byte
	key      KeyPair
	password []byte
	r        kyber.Scalar
}

// NewUserRegister creates a registration session for the given userID. If key
// is nil (recommended), it is generated. A key should never be reused on
// different registrations.
func NewUserRegister(crypto Crypto, userID []byte, key KeyPair) *UserRegister {
	if key == nil {
		key = crypto.GenerateKey(nil)
	}
	return &UserRegister{crypto: crypto, userID: userID, key: key}
}

// Key gives the key used during registration. This is often generated on
// NewUserRegister. It is rarely needed because it comes back on authenticate
// as well.
func (u *UserRegister) Key() KeyPair { return u.key }

// UserRegisterInit is the set of data to pass to the server after calling
// UserRegister.Init. It implements encoding.BinaryMarshaller and
// encoding.BinaryUnmarshaller.
type UserRegisterInit struct {
	UserID []byte
	Alpha  kyber.Point
}

// MarshalBinary implements encoding.BinaryMarshaller.
func (u *UserRegisterInit) MarshalBinary() ([]byte, error) {
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
func (u *UserRegisterInit) UnmarshalBinary(data []byte) (err error) {
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
func (u *UserRegisterInit) FromBytes(crypto Crypto, data []byte) error {
	u.Alpha = crypto.Point()
	return u.UnmarshalBinary(data)
}

// Init creates an init message for the password.
func (u *UserRegister) Init(password []byte) *UserRegisterInit {
	// Set user password
	u.password = password
	// Start OPRF
	init := &UserRegisterInit{UserID: u.userID}
	u.r, init.Alpha = OPRFUserStep1(u.crypto, password)
	return init
}

// UserRegisterComplete is the set of data to pass to the server after calling
// Complete. It implements encoding.BinaryMarshaller and
// encoding.BinaryUnmarshaller.
type UserRegisterComplete struct {
	EnvU []byte
	PubU []byte
}

// MarshalBinary implements encoding.BinaryMarshaller. Error is always nil.
func (u *UserRegisterComplete) MarshalBinary() ([]byte, error) {
	b := newBuf(nil)
	b.WriteVarBytes(u.EnvU)
	b.WriteVarBytes(u.PubU)
	return b.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryMarshaller. This can return
// ErrUnmarshalMoreData if the data is too big.
func (u *UserRegisterComplete) UnmarshalBinary(data []byte) (err error) {
	b := newBuf(data)
	if u.EnvU, err = b.ReadVarBytes(); err == nil {
		if u.PubU, err = b.ReadVarBytes(); err == nil {
			err = b.AssertUnmarshalNoMoreData()
		}
	}
	return
}

// Complete is called after receiving the server init results. The result of
// this call should be passed back to the server.
func (u *UserRegister) Complete(s *ServerRegisterInit) *UserRegisterComplete {
	if len(u.password) == 0 {
		panic("No password, was init run?")
	}
	// Finish up OPRF
	rwdU := OPRFUserStep3(u.crypto, u.password, u.r, s.V, s.Beta)
	// Generate a key pair from rwdU seed
	authEncKey := u.crypto.GenerateKey(rwdU)
	// Generate the envelope by encrypting my pair and server pub w/ the OPRF result as the key
	plain := append(u.key.ToBytes(), s.PublicKey...)
	envU, err := u.crypto.AuthEncrypt(authEncKey, plain)
	if err != nil {
		panic(err)
	}
	return &UserRegisterComplete{EnvU: envU, PubU: u.key.PublicKeyBytes()}
}

// ServerRegister is the server-side session for registration with a user. This
// should be created for each user registration and never reused. Once created
// via NewServerRegister, Init should be called with the value from the user
// side and then the result should be passed back to the user. The user-side's
// next value should be passed to Complete and the results of Complete should
// be stored by the server.
type ServerRegister struct {
	crypto Crypto
	key    KeyPair
	kU     kyber.Scalar
	userID []byte
}

// NewServerRegister creates a ServerRegister with the given key. The key can
// be the same as used for other registrations.
func NewServerRegister(crypto Crypto, key KeyPair) *ServerRegister {
	return &ServerRegister{
		crypto: crypto,
		key:    key,
		kU:     crypto.Scalar().Pick(crypto.RandomStream()),
	}
}

// ServerRegisterInit is the result of Init to be passed to the user. It
// implements encoding.BinaryMarshaller and encoding.BinaryUnmarshaller.
type ServerRegisterInit struct {
	PublicKey []byte
	V         kyber.Point
	Beta      kyber.Point
}

// MarshalBinary implements encoding.BinaryMarshaller.
func (s *ServerRegisterInit) MarshalBinary() ([]byte, error) {
	b := newBuf(nil)
	b.WriteVarBytes(s.PublicKey)
	if err := b.WritePoint(s.V); err != nil {
		return nil, err
	} else if err = b.WritePoint(s.Beta); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryMarshaller. The V and Beta fields
// must be non-nil before calling this. Otherwise, use FromBytes.  This can
// return ErrUnmarshalMoreData if the data is too big.
func (s *ServerRegisterInit) UnmarshalBinary(data []byte) (err error) {
	b := newBuf(data)
	if s.PublicKey, err = b.ReadVarBytes(); err == nil {
		if err = b.ReadPoint(s.V); err == nil {
			if err = b.ReadPoint(s.Beta); err == nil {
				err = b.AssertUnmarshalNoMoreData()
			}
		}
	}
	return
}

// FromBytes populates this from bytes. This can return ErrUnmarshalMoreData if
// the data is too big.
func (s *ServerRegisterInit) FromBytes(crypto Crypto, data []byte) error {
	s.V, s.Beta = crypto.Point(), crypto.Point()
	return s.UnmarshalBinary(data)
}

// Init is called with the first data received from the user side. The response
// should be sent back to the user.
func (s *ServerRegister) Init(u *UserRegisterInit) *ServerRegisterInit {
	// Store the user ID
	s.userID = u.UserID
	// Do server-side OPRF step
	i := &ServerRegisterInit{PublicKey: s.key.PublicKeyBytes()}
	i.V, i.Beta = OPRFServerStep2(s.crypto, u.Alpha, s.kU)
	return i
}

// ServerRegisterComplete is the completed set of data that should be stored by
// the server on successful registration.
type ServerRegisterComplete struct {
	UserID []byte
	// Same as given originally, can be global
	Key        KeyPair
	EnvU, PubU []byte
	KU         kyber.Scalar
}

// Complete takes the last info from the user and returns a st of data that
// must be stored by the server.
func (s *ServerRegister) Complete(u *UserRegisterComplete) *ServerRegisterComplete {
	// Just return the stuff as complete
	return &ServerRegisterComplete{UserID: s.userID, Key: s.key, EnvU: u.EnvU, PubU: u.PubU, KU: s.kU}
}
