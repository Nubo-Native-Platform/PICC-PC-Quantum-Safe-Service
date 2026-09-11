// Package pqcrypto implements hybrid quantum-safe encryption, combining a
// classical X25519 (ECDH) key exchange with post-quantum ML-KEM-768 (FIPS
// 203) key encapsulation, per the defense-in-depth pattern recommended
// during the PQC transition period: even if one of the two algorithms is
// ever broken, the other still protects the derived key.
//
//	X25519 ECDH shared secret ┐
//	                          ├─► HKDF-SHA256 ─► AES-256 key ─► AES-256-GCM
//	ML-KEM-768 shared secret  ┘
package pqcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/hkdf"
)

// hkdfInfo provides domain separation for the key derivation step so this
// key material can never be confused with a key derived elsewhere for a
// different purpose, even from the same shared secrets.
const hkdfInfo = "pq-crypto-service:hybrid-x25519-mlkem768:v1"

// KeyPair holds a long-lived hybrid keypair: one X25519 keypair for the
// classical ECDH leg, and one ML-KEM-768 keypair for the post-quantum leg.
type KeyPair struct {
	X25519Public  *ecdh.PublicKey
	X25519Private *ecdh.PrivateKey
	MLKEMPublic   *mlkem768.PublicKey
	MLKEMPrivate  *mlkem768.PrivateKey
}

// GenerateKeyPair creates a fresh hybrid X25519 + ML-KEM-768 keypair.
func GenerateKeyPair() (*KeyPair, error) {
	x25519Priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	mlkemPub, mlkemPriv, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		X25519Public:  x25519Priv.PublicKey(),
		X25519Private: x25519Priv,
		MLKEMPublic:   mlkemPub,
		MLKEMPrivate:  mlkemPriv,
	}, nil
}

// MLKEMPublicKeyBytes returns the marshaled ML-KEM-768 public key.
func (k *KeyPair) MLKEMPublicKeyBytes() ([]byte, error) {
	return k.MLKEMPublic.MarshalBinary()
}

// X25519PublicKeyBytes returns the raw 32-byte X25519 public key.
func (k *KeyPair) X25519PublicKeyBytes() []byte {
	return k.X25519Public.Bytes()
}

// EncryptResult bundles everything the caller needs to later decrypt.
type EncryptResult struct {
	KEMCiphertext         []byte // ML-KEM-768 encapsulated ciphertext
	X25519EphemeralPublic []byte // sender's ephemeral X25519 public key
	Nonce                 []byte // AES-GCM nonce
	Ciphertext            []byte // AES-GCM ciphertext (tag included)
}

// deriveAESKey combines the ML-KEM shared secret and the X25519 ECDH shared
// secret and stretches them into a single 256-bit AES key via HKDF-SHA256.
// Concatenating both secrets before the KDF means an attacker needs to
// break BOTH the classical and the post-quantum leg to recover the key.
func deriveAESKey(mlkemSharedSecret, x25519SharedSecret []byte) ([]byte, error) {
	combined := make([]byte, 0, len(mlkemSharedSecret)+len(x25519SharedSecret))
	combined = append(combined, mlkemSharedSecret...)
	combined = append(combined, x25519SharedSecret...)

	kdf := hkdf.New(sha256.New, combined, nil, []byte(hkdfInfo))
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt performs the hybrid key exchange against the recipient's public
// keys (ML-KEM encapsulation + a fresh ephemeral X25519 ECDH exchange),
// derives an AES-256 key via HKDF, and AES-256-GCM encrypts plaintext.
func Encrypt(recipientMLKEMPub *mlkem768.PublicKey, recipientX25519Pub *ecdh.PublicKey, plaintext []byte) (*EncryptResult, error) {
	// --- Post-quantum leg: ML-KEM encapsulation ---
	kemCT := make([]byte, mlkem768.CiphertextSize)
	mlkemSS := make([]byte, mlkem768.SharedKeySize)

	seed := make([]byte, mlkem768.EncapsulationSeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, err
	}
	recipientMLKEMPub.EncapsulateTo(kemCT, mlkemSS, seed)

	// --- Classical leg: ephemeral X25519 ECDH ---
	ephemeralPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	x25519SS, err := ephemeralPriv.ECDH(recipientX25519Pub)
	if err != nil {
		return nil, err
	}

	// --- Combine both legs into one AES-256 key ---
	aesKey, err := deriveAESKey(mlkemSS, x25519SS)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &EncryptResult{
		KEMCiphertext:         kemCT,
		X25519EphemeralPublic: ephemeralPriv.PublicKey().Bytes(),
		Nonce:                 nonce,
		Ciphertext:            ciphertext,
	}, nil
}

// Decrypt performs ML-KEM decapsulation and the matching X25519 ECDH using
// the recipient's private keys, re-derives the AES-256 key via HKDF, and
// AES-256-GCM decrypts.
func Decrypt(mlkemPriv *mlkem768.PrivateKey, x25519Priv *ecdh.PrivateKey, kemCiphertext, x25519EphemeralPublic, nonce, ciphertext []byte) ([]byte, error) {
	if len(kemCiphertext) != mlkem768.CiphertextSize {
		return nil, errors.New("invalid kem ciphertext length")
	}

	// --- Post-quantum leg ---
	mlkemSS := make([]byte, mlkem768.SharedKeySize)
	mlkemPriv.DecapsulateTo(mlkemSS, kemCiphertext)

	// --- Classical leg ---
	senderEphemeralPub, err := ecdh.X25519().NewPublicKey(x25519EphemeralPublic)
	if err != nil {
		return nil, errors.New("invalid x25519 ephemeral public key")
	}
	x25519SS, err := x25519Priv.ECDH(senderEphemeralPub)
	if err != nil {
		return nil, errors.New("x25519 key exchange failed")
	}

	// --- Combine + derive ---
	aesKey, err := deriveAESKey(mlkemSS, x25519SS)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce length")
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: authentication error or tampered data")
	}

	return plaintext, nil
}
