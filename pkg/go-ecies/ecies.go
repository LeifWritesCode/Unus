package goecies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

const (
	compressed_ecpub_len = 33
	hmac_sha256_len      = 32
	salt_len             = 16
)

// readEntropy generates n bytes of entropy
func read_entropy(n int) []byte {
	entropy := make([]byte, n)
	rand.Read(entropy)
	return entropy
}

// padding_pkcs7_add appends up-to a 16-byte block of padding to a message,
// where the value used to pad is the same as the length of the padding.
// Returns the padded message.
func padding_pkcs7_add(message []byte) []byte {
	modulo := len(message) % aes.BlockSize
	pad_byte := byte(aes.BlockSize - modulo)

	padding := make([]byte, pad_byte)
	for i := range padding {
		padding[i] = pad_byte
	}

	return append(message, padding...)
}

// padding_pkcs7_rem removes n bytes of padding from message, determined by the
// final byte of message. Returns the original message without padding.
func padding_pkcs7_rem(message []byte) []byte {
	message_length := len(message)
	pad_byte := message[message_length-1]

	original_length := message_length - int(pad_byte)
	return message[:original_length]
}

// aes_encrypt performs aes encryption of message using key
func aes_encrypt(key []byte, message []byte) ([]byte, []byte, error) {
	cipher_block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	padded_message := padding_pkcs7_add(message)

	encrypted_length := len(padded_message)
	encrypted_message := make([]byte, encrypted_length)

	iv := make([]byte, aes.BlockSize)
	if copy(iv, read_entropy(aes.BlockSize)) != aes.BlockSize {
		return nil, nil, errors.New("not enough entropy")
	}

	cbc := cipher.NewCBCEncrypter(cipher_block, iv)
	cbc.CryptBlocks(encrypted_message, padded_message)

	return encrypted_message, iv, nil
}

// aes_decrypt performs aes decryption of message using key
func aes_decrypt(key, iv, message []byte) ([]byte, error) {
	cipher_block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded_message := make([]byte, len(message))
	cbc := cipher.NewCBCDecrypter(cipher_block, iv)
	cbc.CryptBlocks(padded_message, message)

	original_message := padding_pkcs7_rem(padded_message)

	return original_message, nil
}

// read_out_components splits an ECIES-derived message into its constituent
// parts
func read_out_components(message []byte) ([]byte, []byte, []byte, []byte, []byte, []byte) {
	offset := 0
	length := compressed_ecpub_len
	compressed_public_key := message[offset:length]

	offset = length
	length += hmac_sha256_len
	tag := message[offset:length]

	offset = length
	length += salt_len
	aes_salt := message[offset:length]

	offset = length
	length += salt_len
	hmac_salt := message[offset:length]

	offset = length
	length += aes.BlockSize
	iv := message[offset:length]

	offset = length
	encrypted_message := message[offset:]

	return compressed_public_key, tag, aes_salt, hmac_salt, iv, encrypted_message
}

// EncryptEphemeral performs ECIES encryption of the message using an ephemeral
// key pair for the sender
func EncryptEphemeral(receiver_key *_ECPublicKey, message []byte) ([]byte, error) {
	ephemeral_sender_key, err := NewECPrivateKey()
	if err != nil {
		return nil, err
	}

	return Encrypt(ephemeral_sender_key, receiver_key, message)
}

// Encrypt performs ECIES encryption of the message using the senders EC
// private key and the receivers EC public key. If the message length is not a
// multiple of 16, it will be padded with bytes according to PKCS#7. If either
// of the keys given are invalid, an error is returned. If EC public key
// compression fails, an error is returned. If the encryption fails, an error
// is returned.
func Encrypt(sender_key *_ECPrivateKey, receiver_key *_ECPublicKey, message []byte) ([]byte, error) {
	// perform ECDHKA
	shared_secret, err := sender_key.Agree(receiver_key)
	if err != nil {
		return nil, err
	}

	// initialise KDF
	kdf := NewKDF(KDFParams{
		key:        shared_secret,
		hash:       sha256.New,
		iterations: 310000,
		length:     32,
	})

	// derive symmetric key
	aes_salt := read_entropy(16)
	aes_key := kdf.DeriveKey(aes_salt)

	// encrypt
	encrypted_message, iv, err := aes_encrypt(aes_key, message)
	if err != nil {
		return nil, err
	}

	// derive hmac key
	hmac_salt := read_entropy(16)
	hmac_key := kdf.DeriveKey(hmac_salt)

	// calculate tag
	hmac_alg := hmac.New(sha256.New, hmac_key)
	hmac_alg.Write(encrypted_message)
	tag := hmac_alg.Sum(nil)

	// compress the key used to send this message
	compressed_public_key, err := sender_key.Compress()
	if err != nil {
		return nil, err
	}

	// encode as kP | tag | aes_salt | hmac_salt | message
	cryptogram := make([]byte, 0)
	cryptogram = append(cryptogram, compressed_public_key...)
	cryptogram = append(cryptogram, tag...)
	cryptogram = append(cryptogram, aes_salt...)
	cryptogram = append(cryptogram, hmac_salt...)
	cryptogram = append(cryptogram, iv...)
	cryptogram = append(cryptogram, encrypted_message...)

	return cryptogram, nil
}

// Decrypt decrypts the ECIES-derived message, using the receive_key in the
// ECDH key agreement step. The ECIES-derived message contains the senders EC
// public key, the HMAC tag, a salt each for deriving the AES and HMAC keys and
// the IV used in the AES encryption step. If the message is not at least long
// enough to contain these data, an error is returned. Additionally, if either
// of the keys given are invalid, an error is returned. Lastly, if the message
// has been tampered with, an error is returned.
func Decrypt(receiver_key *_ECPrivateKey, message []byte) ([]byte, error) {
	// slice up the cryptogram into the necessary chunks
	compressed_public_key, tag, aes_salt, hmac_salt, iv, encrypted_message := read_out_components(message)

	// recreate the sender ephemeral public key
	sender_public_key, err := NewECPublicKeyFromCompressed(receiver_key.Curve, compressed_public_key)
	if err != nil {
		return nil, err
	}

	// perform ECDHKA
	shared_secret, err := receiver_key.Agree(sender_public_key)
	if err != nil {
		return nil, err
	}

	// initialise KDF
	kdf := NewKDF(KDFParams{
		key:        shared_secret,
		hash:       sha256.New,
		iterations: 310000,
		length:     32,
	})

	// derive hmac key
	hmac_key := kdf.DeriveKey(hmac_salt)

	// calculate tag
	hmac_alg := hmac.New(sha256.New, hmac_key)
	hmac_alg.Write(encrypted_message)
	expected_tag := hmac_alg.Sum(nil)

	// verify the tags match
	if !hmac.Equal(expected_tag, tag) {
		err := errors.New("invalid key or cryptogram")
		return nil, err
	}

	// derive symmetric key
	aes_key := kdf.DeriveKey(aes_salt)

	// decrypt
	original_message, err := aes_decrypt(aes_key, iv, encrypted_message)
	if err != nil {
		return nil, err
	}

	return original_message, nil
}
