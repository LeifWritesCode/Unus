package goecies

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

// ECPublicKey encapsulates an elliptice curve public key. It is made up of its
// x and y coordinates, and the curve from which they were derived.
type _ECPublicKey struct {
	elliptic.Curve
	x *big.Int
	y *big.Int
}

// NewECPublicKeyFromCompressed attempts to unmarshal the compressed EC public
// key bytes onto the given curve. If the key and/or curve are invalid, an
// error is returned.
func NewECPublicKeyFromCompressed(curve elliptic.Curve, compressed []byte) (*_ECPublicKey, error) {
	x, y := elliptic.UnmarshalCompressed(curve, compressed)
	if !curve.IsOnCurve(x, y) {
		err := errors.New("invalid key")
		return nil, err
	}

	return &_ECPublicKey{
		Curve: curve,
		x:     x,
		y:     y,
	}, nil
}

// Compress compresses the EC public key into 257 bits (32 bytes)
func (ecpub *_ECPublicKey) Compress() ([]byte, error) {
	return elliptic.MarshalCompressed(ecpub.Curve, ecpub.x, ecpub.y), nil
}
