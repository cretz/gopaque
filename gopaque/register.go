package gopaque

import "go.dedis.ch/kyber"

type UserRegister struct {
	crypto   Crypto
	userID   []byte
	key      KeyPair
	password []byte
	r        kyber.Scalar
}

func NewUserRegister(crypto Crypto, userID []byte) *UserRegister {
	return &UserRegister{crypto: crypto, userID: userID, key: crypto.GenerateKey(nil)}
}

type UserRegisterInit struct {
	UserID []byte
	Alpha  kyber.Point
}

func (u *UserRegister) Init(password []byte) *UserRegisterInit {
	// Set user password
	u.password = password
	// Start OPRF
	init := &UserRegisterInit{UserID: u.userID}
	u.r, init.Alpha = oprfUserStep1(u.crypto, password)
	return init
}

type UserRegisterComplete struct {
	EnvU []byte
	PubU []byte
}

func (u *UserRegister) Complete(s *ServerRegisterInit) *UserRegisterComplete {
	if len(u.password) == 0 {
		panic("No password, was init run?")
	}
	// Finish up OPRF
	rwdU := oprfUserStep3(u.crypto, u.password, u.r, s.V, s.Beta)
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

type ServerRegister struct {
	crypto Crypto
	key    KeyPair
	kU     kyber.Scalar
	userID []byte
}

func NewServerRegister(crypto Crypto, key KeyPair) *ServerRegister {
	return &ServerRegister{
		crypto: crypto,
		key:    key,
		kU:     crypto.Scalar().Pick(crypto.RandomStream()),
	}
}

type ServerRegisterInit struct {
	PublicKey []byte
	V         kyber.Point
	Beta      kyber.Point
}

func (s *ServerRegister) Init(u *UserRegisterInit) *ServerRegisterInit {
	// Store the user ID
	s.userID = u.UserID
	// Do server-side OPRF step
	i := &ServerRegisterInit{PublicKey: s.key.PublicKeyBytes()}
	i.V, i.Beta = oprfServerStep2(s.crypto, u.Alpha, s.kU)
	return i
}

type ServerRegisterComplete struct {
	UserID     []byte
	EnvU, PubU []byte
	KU         kyber.Scalar
	// Same as given originally, can be global
	Key KeyPair
}

func (s *ServerRegister) Complete(u *UserRegisterComplete) *ServerRegisterComplete {
	// Just return the stuff as complete
	return &ServerRegisterComplete{UserID: s.userID, EnvU: u.EnvU, PubU: u.PubU, KU: s.kU, Key: s.key}
}
