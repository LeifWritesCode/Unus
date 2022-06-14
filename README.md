# unus

Unus (meaning 'one' in Latin) is a small web-application and associated cryptography package (go-ecies) that enables straight-forward and secure secret sharing between two parties, requiring just a passphrase to retrieve their secret.

## Install

`go install code.leif.uk/lwg/unus`

Unus was made with Go 1.17, however versions as recent as 1.13 should suffice.

## Running unus

If executing from source, `go run ./cmd/unus`.

If you've `go install`'d unus, run `unus` as you would other go binaries. This assumes that `$GOPATH/bin` is on your path. If it is not, use `$GOPATH/bin/unus` instead.

Navigate to `127.0.0.1:8080` in your browser of choice for instructions on how to use unus in practice.

# go-ecies

Unus contains a small cryptography package, go-ecies, providing an implementation of an Elliptic Curve Integrated Encryption Scheme. These are sometimes referred to as an Elliptic Curve _Augmented_ Encryption Scheme, or simply an Integrated Encryption Scheme.

## Quick Start

```
package main

import (
	"log"

	ecies "code.leif.uk/lwg/unus/pkg/go-ecies"
)

func main() {
	sender_key, err := ecies.NewECPrivateKey()
	if err != nil {
		panic(err)
	}
	log.Println("alice has a private key")

	recipient_key, err := ecies.NewECPrivateKey()
	if err != nil {
		panic(err)
	}
	log.Println("bob has a private key, of which alice has the public half")

	message := "MySuperSecretMessage"
	message_bytes := []byte(message)
	log.Println("alice prepares a message to send to bob")
	log.Printf("her message reads: %s\n", message)

	// if the sender doesn't have (or doesn't wish to use) a static key
	// use ecies.EncryptEphemeral instead
	cryptogram, err := ecies.Encrypt(sender_key, recipient_key.PublicKey(), message_bytes)
	if err != nil {
		panic(err)
	}
	log.Println("alice encrypts her message, using her private key and bobs public key")
	log.Printf("it looks like this: %v\n", cryptogram)

	plaintext, err := ecies.Decrypt(recipient_key, cryptogram)
	recieved_message := string(plaintext)
	if err != nil {
		panic(err)
	}
	log.Println("bob decrypts alice's message, using his private key and alice's public key (which is embedded in her encrypted message)")
	log.Printf("bob received: %s\n", recieved_message)

	if recieved_message == message {
		log.Println("hooray, they're the same! alice has successfully transmitted her message to bob, securely")
	} else {
		panic("oops, something went wrong...")
	}
}
```