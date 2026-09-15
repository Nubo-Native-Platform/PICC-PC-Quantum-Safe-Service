package pqcrypto

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// storedKeyPair is the on-disk/in-env JSON representation of a hybrid keypair.
// Only private keys need to be stored: both X25519 and ML-KEM-768 public
// keys can be deterministically derived from their private key on load.
type storedKeyPair struct {
	X25519Private string `json:"x25519_private"` // base64, 32 bytes
	MLKEMPrivate  string `json:"mlkem_private"`  // base64
}

// SaveKeyPair writes both private keys to path as base64-encoded JSON,
// with owner-only permissions. The parent directory is created if needed.
func SaveKeyPair(k *KeyPair, path string) error {
	mlkemBytes, err := k.MLKEMPrivate.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal mlkem private key: %w", err)
	}

	stored := storedKeyPair{
		X25519Private: base64.StdEncoding.EncodeToString(k.X25519Private.Bytes()),
		MLKEMPrivate:  base64.StdEncoding.EncodeToString(mlkemBytes),
	}

	data, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("marshal key file: %w", err)
	}

	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create key directory: %w", err)
		}
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	return nil
}

// LoadKeyPairFromJSON parses key pair JSON and derives both public keys from the private keys.
func LoadKeyPairFromJSON(data []byte) (*KeyPair, error) {
	var stored storedKeyPair
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("parse key json: %w", err)
	}

	x25519Bytes, err := base64.StdEncoding.DecodeString(stored.X25519Private)
	if err != nil {
		return nil, fmt.Errorf("decode x25519 private key: %w", err)
	}
	x25519Priv, err := ecdh.X25519().NewPrivateKey(x25519Bytes)
	if err != nil {
		return nil, fmt.Errorf("unpack x25519 private key: %w", err)
	}

	mlkemBytes, err := base64.StdEncoding.DecodeString(stored.MLKEMPrivate)
	if err != nil {
		return nil, fmt.Errorf("decode mlkem private key: %w", err)
	}
	mlkemPriv := new(mlkem768.PrivateKey)
	if err := mlkemPriv.Unpack(mlkemBytes); err != nil {
		return nil, fmt.Errorf("unpack mlkem private key: %w", err)
	}
	mlkemPub, ok := mlkemPriv.Public().(*mlkem768.PublicKey)
	if !ok {
		return nil, fmt.Errorf("derive mlkem public key: unexpected type")
	}

	return &KeyPair{
		X25519Public:  x25519Priv.PublicKey(),
		X25519Private: x25519Priv,
		MLKEMPublic:   mlkemPub,
		MLKEMPrivate:  mlkemPriv,
	}, nil
}

// LoadKeyPair reads a hybrid keypair previously written by SaveKeyPair or provided as a file.
func LoadKeyPair(path string) (*KeyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	return LoadKeyPairFromJSON(data)
}

// LoadOrGenerateKeyPair loads a keypair with clear precedence:
// 1. Direct JSON string if passed in optional keyJSON (e.g. from MLKEM_KEY_JSON env var)
// 2. File at path if configured and exists (e.g. from MLKEM_KEY_PATH)
// 3. Standard fallback file locations (/app/keys/mlkem_private.key, keys/mlkem_private.key)
// 4. If no key is found, dynamically generates a fresh hybrid keypair (GenerateKeyPair()).
//    If a non-empty path is provided, attempts to persist the keypair so subsequent starts reload it.
func LoadOrGenerateKeyPair(path string, keyJSON ...string) (k *KeyPair, source string, err error) {
	// 1. Check direct JSON string (from env var)
	if len(keyJSON) > 0 && keyJSON[0] != "" {
		k, err = LoadKeyPairFromJSON([]byte(keyJSON[0]))
		if err == nil {
			return k, "environment variable (MLKEM_KEY_JSON)", nil
		}
	}

	// 2. Check path if configured and exists
	if path != "" {
		if _, statErr := os.Stat(path); statErr == nil {
			k, err = LoadKeyPair(path)
			if err == nil {
				return k, fmt.Sprintf("file (%s)", path), nil
			}
		}
	}

	// 3. Check standard fallback file locations
	fallbackPaths := []string{
		"/app/keys/mlkem_private.key",
		"keys/mlkem_private.key",
		"./keys/mlkem_private.key",
	}
	for _, fp := range fallbackPaths {
		if fp != path {
			if _, statErr := os.Stat(fp); statErr == nil {
				k, err = LoadKeyPair(fp)
				if err == nil {
					return k, fmt.Sprintf("fallback file (%s)", fp), nil
				}
			}
		}
	}

	// 4. Dynamically generate a fresh, cryptographically secure keypair
	k, err = GenerateKeyPair()
	if err != nil {
		return nil, "", fmt.Errorf("generate keypair: %w", err)
	}

	// If path is specified, attempt to persist it (best-effort)
	if path != "" {
		if saveErr := SaveKeyPair(k, path); saveErr == nil {
			return k, fmt.Sprintf("newly generated and persisted to file (%s)", path), nil
		}
	}

	return k, "dynamically generated ephemeral keypair", nil
}

