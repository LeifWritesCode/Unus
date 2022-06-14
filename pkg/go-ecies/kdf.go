package goecies

import (
	"crypto/sha256"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

var (
	default_kdf_params = KDFParams{
		hash:       sha256.New,
		key:        read_entropy(32),
		iterations: 3000000,
		length:     32,
	}
)

// KDFParams encapsulates the parameters required to perform key derivation
// using PBKDF2
type KDFParams struct {
	hash       func() hash.Hash
	key        []byte
	iterations int
	length     int
}

// KDF encapsulates the key derivation function
type _KDF struct {
	hash       func() hash.Hash
	key        []byte
	iterations int
	length     int
}

// NewDefaultKDF initialises a new instance of KDF using the default parameters
// and a random key
func NewDefaultKDF() *_KDF {
	return NewKDF(default_kdf_params)
}

// NewKDF initialises a new instance of KDF using the given parameters
func NewKDF(params KDFParams) *_KDF {
	return &_KDF{
		hash:       params.hash,
		key:        params.key,
		iterations: params.iterations,
		length:     params.length,
	}
}

// DeriveKey performs key derivation using PBKDF2 and the parameters given
// during initialisation. Additionally, if not nil, the salt will be used.
func (kdf *_KDF) DeriveKey(salt []byte) []byte {
	return pbkdf2.Key(kdf.key, salt, kdf.iterations, kdf.length, kdf.hash)
}
