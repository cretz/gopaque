package gopaque_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/cretz/gopaque/gopaque"
	"go.dedis.ch/kyber/v3"
)

// This example is a more complex example showing marshalling and using separate
// user and server-side connections.
func Example_withConnPipe() {
	// Create already-connected user/server pipe and a bool to tell when closed
	userConn, serverConn := net.Pipe()
	defer userConn.Close()
	serverClosed := false
	defer func() {
		serverClosed = true
		serverConn.Close()
	}()

	// Run the server
	go func() {
		if err := RunServer(serverConn); err != nil && !serverClosed {
			fmt.Printf("Server failed: %v\n", err)
		}
	}()

	// Register a user. The returned key is just for checking later for this
	// example. In general there is no reason to keep it around as it's sent
	// back on auth.
	key, err := UserSideRegister(userConn, "myuser", "mypass")
	if err != nil {
		panic(err)
	}

	// Now auth the user. We are ignoring the returned key exchange info here
	// but could capture it and use it's shared secret if we wanted.
	authInfo, _, err := UserSideAuth(userConn, "myuser", "mypass")
	if err != nil {
		panic(err)
	}

	// Confirm the key pair is what we registered with
	if !key.Equal(authInfo.UserPrivateKey) {
		panic("Invalid key")
	}

	// Output:
}

var crypto = gopaque.CryptoDefault

func UserSideRegister(c net.Conn, username, password string) (kyber.Scalar, error) {
	// Create a registration session
	userReg := gopaque.NewUserRegister(crypto, []byte(username), nil)

	// Create init message and send it over
	if err := sendMessage(c, 'r', userReg.Init([]byte(password))); err != nil {
		return nil, err
	}

	// Receive the server message
	var serverInit gopaque.ServerRegisterInit
	if err := recvMessage(c, &serverInit); err != nil {
		return nil, err
	}

	// Create user complete message and send it over, then we're done
	return userReg.PrivateKey(), sendMessage(c, 'r', userReg.Complete(&serverInit))
}

func UserSideAuth(c net.Conn, username, password string) (*gopaque.UserAuthFinish, *gopaque.KeyExchangeSigma, error) {
	// Create auth session w/ built in key exchange
	kex := gopaque.NewKeyExchangeSigma(crypto)
	userAuth := gopaque.NewUserAuth(crypto, []byte(username), kex)

	// Create init message and send it over
	if userInit, err := userAuth.Init([]byte(password)); err != nil {
		return nil, nil, err
	} else if err = sendMessage(c, 'a', userInit); err != nil {
		return nil, nil, err
	}

	// Receive the server message
	var serverComplete gopaque.ServerAuthComplete
	if err := recvMessage(c, &serverComplete); err != nil {
		return nil, nil, err
	}

	// Verify user side and since we embedded a key exchange, there is one last
	// message to send to the server.
	if userFinish, userComplete, err := userAuth.Complete(&serverComplete); err != nil {
		return nil, nil, err
	} else if err = sendMessage(c, 'a', userComplete); err != nil {
		return nil, nil, err
	} else {
		return userFinish, kex, nil
	}
}

func RunServer(c net.Conn) error {
	// This stores the registered users
	registeredUsers := map[string]*gopaque.ServerRegisterComplete{}
	// Create a key pair for our server
	key := crypto.NewKey(nil)
	// Run forever handling register and auth
	for {
		// Get the next user message
		msgType, msgBytes, err := recvMessageBytes(c)
		if err != nil {
			return err
		}
		// Handle different message types
		switch msgType {
		// Handle registration...
		case 'r':
			if regComplete, err := ServerSideRegister(c, key, msgBytes); err != nil {
				return err
			} else if username := string(regComplete.UserID); registeredUsers[username] != nil {
				return fmt.Errorf("Username '%v' already exists", username)
			} else {
				registeredUsers[username] = regComplete
			}
			// Handle auth...
		case 'a':
			if err := ServerSideAuth(c, msgBytes, registeredUsers); err != nil {
				return err
			}
		default:
			return fmt.Errorf("Unknown message type: %v", msgType)
		}
	}
}

func ServerSideRegister(c net.Conn, key kyber.Scalar, userInitBytes []byte) (*gopaque.ServerRegisterComplete, error) {
	// Create the registration session
	serverReg := gopaque.NewServerRegister(crypto, key)
	// Unmarshal user init, create server init, and send back
	var userInit gopaque.UserRegisterInit
	if err := userInit.FromBytes(crypto, userInitBytes); err != nil {
		return nil, err
	} else if err = sendMessage(c, 'r', serverReg.Init(&userInit)); err != nil {
		return nil, err
	}
	// Get back the user complete and complete things ourselves
	var userComplete gopaque.UserRegisterComplete
	if err := recvMessage(c, &userComplete); err != nil {
		return nil, err
	}
	return serverReg.Complete(&userComplete), nil
}

func ServerSideAuth(c net.Conn, userInitBytes []byte, registeredUsers map[string]*gopaque.ServerRegisterComplete) error {
	// Create the server auth w/ an embedded key exchange. We could store this
	// key exchange if we wanted access to the shared secret afterwards.
	serverAuth := gopaque.NewServerAuth(crypto, gopaque.NewKeyExchangeSigma(crypto))
	// Parse the user init bytes
	var userInit gopaque.UserAuthInit
	if err := userInit.FromBytes(crypto, userInitBytes); err != nil {
		return err
	}
	// Load up the registration info
	regComplete := registeredUsers[string(userInit.UserID)]
	if regComplete == nil {
		return fmt.Errorf("Username not found")
	}
	// Complete the auth and send it back
	if serverComplete, err := serverAuth.Complete(&userInit, regComplete); err != nil {
		return err
	} else if err = sendMessage(c, 'a', serverComplete); err != nil {
		return err
	}
	// Since we are using an embedded key exchange, we have one more step which
	// receives another user message and validates it.
	var userComplete gopaque.UserAuthComplete
	if err := recvMessage(c, &userComplete); err != nil {
		return err
	}
	return serverAuth.Finish(&userComplete)
}

// Below is just a very simple, insecure conn messager

func sendMessage(c net.Conn, msgType byte, msg gopaque.Marshaler) error {
	if msgBytes, err := msg.ToBytes(); err != nil {
		return err
	} else if _, err = c.Write([]byte{msgType}); err != nil {
		return err
	} else if err = binary.Write(c, binary.BigEndian, uint32(len(msgBytes))); err != nil {
		return err
	} else if _, err = c.Write(msgBytes); err != nil {
		return err
	}
	return nil
}

func recvMessage(c net.Conn, msg gopaque.Marshaler) error {
	if _, msgBytes, err := recvMessageBytes(c); err != nil {
		return err
	} else {
		return msg.FromBytes(crypto, msgBytes)
	}
}

func recvMessageBytes(c net.Conn) (msgType byte, msg []byte, err error) {
	typeAndSize := make([]byte, 5)
	if _, err = io.ReadFull(c, typeAndSize); err == nil {
		msgType = typeAndSize[0]
		msg = make([]byte, binary.BigEndian.Uint32(typeAndSize[1:]))
		_, err = io.ReadFull(c, msg)
	}
	return
}
