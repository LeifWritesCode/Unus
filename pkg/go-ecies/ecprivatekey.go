package goecies

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// ECPrivateKey encapsulates an elliptic curve private key. It is made up of
// its private bytes d and the nested ECPublicKey. The nested public key
// maintains a record of the curve, as well as the x and y coordinates derived
// from it.
type _ECPrivateKey struct {
	*_ECPublicKey
	d *big.Int
}

// NewECPrivateKey generates an EC private key on the NIST P-256 curve using
// an appropriate source of entropy. An error is returned if a failure of the
// entropy source occurs.
func NewECPrivateKey() (*_ECPrivateKey, error) {
	curve := elliptic.P256()

	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		err := fmt.Errorf("key generation failed: %s", err.Error())
		return nil, err
	}

	return &_ECPrivateKey{
		_ECPublicKey: &_ECPublicKey{
			Curve: curve,
			x:     x,
			y:     y,
		},
		d: big.NewInt(0).SetBytes(priv),
	}, nil
}

// NewECPrivateKeyFromBytes generates an EC private key on the NIST P-256 curve
// using the given bytes k as the private component. An error is returned if
// the private bytes k are not at least 256-bits in length. The EC public key
// coordinates arising from this operation is guaranteed to be on the
// associated curve.
func NewECPrivateKeyFromBytes(k []byte) (*_ECPrivateKey, error) {
	if len(k) < 32 {
		err := errors.New("bytes d must be at least 256-bits")
		return nil, err
	}

	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(k)

	return &_ECPrivateKey{
		_ECPublicKey: &_ECPublicKey{
			Curve: curve,
			x:     x,
			y:     y,
		},
		d: big.NewInt(0).SetBytes(k),
	}, nil
}

// Agree performs a Diffie-Hellman key agreement using the given EC private and
// public keys. The agreed key is established as the scalar multiple of the
// private key bytes by the public key coordinates on the associated curve. The
// resulting bytes are appended y to x and subject to one round of SHA-256
// before they are returned. The returned bytes are unsuitable for use as a
// symmetric encryption key as-is, and should instead be used as the input to a
// more robust key derivation function. An error is returned if the curves do
// not match, or if either key does not sit on the curve. The specific nature
// of the error is not exposed in order to protect from privileged information
// leakage.
func (ecpriv *_ECPrivateKey) Agree(ecpub *_ECPublicKey) ([]byte, error) {
	if ecpriv.Curve != ecpub.Curve ||
		!ecpub.Curve.IsOnCurve(ecpub.x, ecpub.y) ||
		!ecpriv.Curve.IsOnCurve(ecpriv.x, ecpriv.y) {
		err := errors.New("unable to validate keys")
		return nil, err
	}

	x, y := ecpriv.Curve.ScalarMult(ecpub.x, ecpub.y, ecpriv.d.Bytes())

	raw := append(x.Bytes(), y.Bytes()...)
	hash := sha256.Sum256(raw)

	return hash[:], nil
}

// Bytes returns the raw private key bytes from ecpriv
func (ecpriv *_ECPrivateKey) Bytes() []byte {
	return ecpriv.d.Bytes()
}

// PublicKey returns the EC public key associated with this private key
func (ecpriv *_ECPrivateKey) PublicKey() *_ECPublicKey {
	return ecpriv._ECPublicKey
}
