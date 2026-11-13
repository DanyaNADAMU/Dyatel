package wireguard

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/curve25519"
)

// GeneratePSK returns a base64 32-byte preshared key.
func GeneratePSK() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// GenerateKeypair returns (base64 priv, base64 pub) for a wg interface.
// Clamping mirrors wireguard-tools so the stored private key stays
// bit-identical to the one the public key was derived from.
func GenerateKeypair() (string, string, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	// wg clamps before deriving the public key.
	priv[0] &= 248
	priv[31] &= 7
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	// wg clamps (b[31] = (b[31] & 127) | 64) — keep the stored private key
	// bit-identical to the one the public key was derived from.
	priv[31] &= 127
	priv[31] |= 64
	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub[:]), nil
}
