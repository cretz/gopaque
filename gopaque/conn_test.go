package gopaque_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/cretz/gopaque/gopaque"
)

// This example is just a simple user registration with in-memory user-side and server-side sessions.
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

	// Register a user. The returned key is just for checking later, in general there is no
	// reason to retrieve it or keep it around as it's sent back on auth.
	key, err := UserSideRegister(userConn, "myuser", "mypass")
	if err != nil {
		panic(err)
	}

	// Now auth the user
	authInfo, err := UserSideAuth(userConn, "myuser", "mypass")
	if err != nil {
		panic(err)
	}

	// Confirm the key pair is what we registered with
	if !bytes.Equal(key.ToBytes(), authInfo.Key.ToBytes()) {
		panic("Invalid key")
	}

	// Output:
}

var crypto = gopaque.CryptoDefault

func UserSideRegister(c net.Conn, username, password string) (gopaque.KeyPair, error) {
	// Create a registration session...
	userReg := gopaque.NewUserRegister(crypto, []byte(username), nil)

	// Create init message and send it over
	initBytes, _ := userReg.Init([]byte(password)).MarshalBinary()
	if err := sendMessage(c, 'r', initBytes); err != nil {
		return nil, err
	}

	// Receive the server message
	var serverInit gopaque.ServerRegisterInit
	if _, serverInitBytes, err := recvMessage(c); err != nil {
		return nil, err
	} else if err = serverInit.FromBytes(crypto, serverInitBytes); err != nil {
		return nil, err
	}

	// Create user complete message and send it over, then we're done
	completeBytes, _ := userReg.Complete(&serverInit).MarshalBinary()
	return userReg.Key(), sendMessage(c, 'r', completeBytes)
}

func UserSideAuth(c net.Conn, username, password string) (*gopaque.UserAuthComplete, error) {
	// Create auth session...
	userAuth := gopaque.NewUserAuth(crypto, []byte(username))

	// Create init message and send it over
	initBytes, _ := userAuth.Init([]byte(password)).MarshalBinary()
	if err := sendMessage(c, 'a', initBytes); err != nil {
		return nil, err
	}

	// Receive the server message
	var serverComplete gopaque.ServerAuthComplete
	if _, serverCompleteBytes, err := recvMessage(c); err != nil {
		return nil, err
	} else if err = serverComplete.FromBytes(crypto, serverCompleteBytes); err != nil {
		return nil, err
	}

	// No more sending, just verify on user side and return
	return userAuth.Complete(&serverComplete)
}

func RunServer(c net.Conn) error {
	// This stores the registered users
	registeredUsers := map[string]*gopaque.ServerRegisterComplete{}
	// Create a key pair for our server
	key := crypto.GenerateKey(nil)
	// Run forever handling register and auth
	for {
		// Get the next user message
		msgType, msg, err := recvMessage(c)
		if err != nil {
			return err
		}
		// Handle different message types
		switch msgType {
		// Handle registration...
		case 'r':
			if regComplete, err := ServerSideRegister(c, key, msg); err != nil {
				return err
			} else if username := string(regComplete.UserID); registeredUsers[username] != nil {
				return fmt.Errorf("Username '%v' already exists", username)
			} else {
				registeredUsers[username] = regComplete
			}
			// Handle auth...
		case 'a':
			if err := ServerSideAuth(c, msg, registeredUsers); err != nil {
				return err
			}
		default:
			return fmt.Errorf("Unknown message type: %v", msgType)
		}
	}
}

func ServerSideRegister(c net.Conn, key gopaque.KeyPair, userInitBytes []byte) (*gopaque.ServerRegisterComplete, error) {
	// Create the registration session
	serverReg := gopaque.NewServerRegister(crypto, key)
	// Unmarshal user init, create server init, and send back
	var userInit gopaque.UserRegisterInit
	if err := userInit.FromBytes(crypto, userInitBytes); err != nil {
		return nil, err
	}
	serverInitBytes, _ := serverReg.Init(&userInit).MarshalBinary()
	if err := sendMessage(c, 'r', serverInitBytes); err != nil {
		return nil, err
	}
	// Get back the user complete and complete things ourselves
	var userComplete gopaque.UserRegisterComplete
	if _, userCompleteBytes, err := recvMessage(c); err != nil {
		return nil, err
	} else if err = userComplete.UnmarshalBinary(userCompleteBytes); err != nil {
		return nil, err
	}
	return serverReg.Complete(&userComplete), nil
}

func ServerSideAuth(c net.Conn, userInitBytes []byte, registeredUsers map[string]*gopaque.ServerRegisterComplete) error {
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
	authCompleteBytes, _ := gopaque.ServerAuth(crypto, &userInit, regComplete).MarshalBinary()
	return sendMessage(c, 'a', authCompleteBytes)
}

// Below is just a very simple, insecure conn messager

func sendMessage(c net.Conn, msgType byte, msg []byte) (err error) {
	if _, err = c.Write([]byte{msgType}); err == nil {
		if err = binary.Write(c, binary.BigEndian, uint32(len(msg))); err == nil {
			_, err = c.Write(msg)
		}
	}
	return
}

func recvMessage(c net.Conn) (msgType byte, msg []byte, err error) {
	typeAndSize := make([]byte, 5)
	if _, err = io.ReadFull(c, typeAndSize); err == nil {
		msgType = typeAndSize[0]
		msg = make([]byte, binary.BigEndian.Uint32(typeAndSize[1:]))
		_, err = io.ReadFull(c, msg)
	}
	return
}
