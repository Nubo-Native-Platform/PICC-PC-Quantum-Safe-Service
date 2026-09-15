package pqcrypto

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDynamicKeyGenerationAndPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "keys", "mlkem_private.key")

	// 1. LoadOrGenerate on non-existent path creates and persists new key
	k1, source1, err := LoadOrGenerateKeyPair(keyPath)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if k1 == nil {
		t.Fatalf("generated key is nil")
	}
	if _, statErr := os.Stat(keyPath); statErr != nil {
		t.Fatalf("expected key file to be persisted at %s, but stat failed: %v", keyPath, statErr)
	}

	pub1, err := k1.MLKEMPublicKeyBytes()
	if err != nil {
		t.Fatalf("failed to get mlkem public key: %v", err)
	}

	// 2. Load again from same path, verify identical keys loaded
	k2, source2, err := LoadOrGenerateKeyPair(keyPath)
	if err != nil {
		t.Fatalf("failed to reload persisted key: %v", err)
	}
	pub2, err := k2.MLKEMPublicKeyBytes()
	if err != nil {
		t.Fatalf("failed to get mlkem public key 2: %v", err)
	}

	if string(pub1) != string(pub2) {
		t.Fatalf("persisted keypair public keys do not match across reloads")
	}

	t.Logf("Key loaded successfully from source: %s (initially: %s)", source2, source1)

	// 3. Test round-trip encryption and decryption
	plaintext := []byte("secret post-quantum payload")
	enc, err := Encrypt(k1.MLKEMPublic, k1.X25519Public, plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	decrypted, err := Decrypt(k2.MLKEMPrivate, k2.X25519Private, enc.KEMCiphertext, enc.X25519EphemeralPublic, enc.Nonce, enc.Ciphertext)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted text mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestLoadKeyPairFromJSON(t *testing.T) {
	orig, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	mlkemBytes, err := orig.MLKEMPrivate.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal mlkem private key: %v", err)
	}

	stored := storedKeyPair{
		X25519Private: base64.StdEncoding.EncodeToString(orig.X25519Private.Bytes()),
		MLKEMPrivate:  base64.StdEncoding.EncodeToString(mlkemBytes),
	}
	jsonData, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("failed to marshal stored key: %v", err)
	}

	k, err := LoadKeyPairFromJSON(jsonData)
	if err != nil {
		t.Fatalf("failed to load key from JSON: %v", err)
	}
	if k.MLKEMPublic == nil || k.X25519Public == nil {
		t.Fatalf("public keys should not be nil")
	}

	origPub, _ := orig.MLKEMPublicKeyBytes()
	loadedPub, _ := k.MLKEMPublicKeyBytes()
	if string(origPub) != string(loadedPub) {
		t.Fatalf("public key mismatch between original and deserialized")
	}
}

func TestLoadOrGenerateWithEnvJSON(t *testing.T) {
	orig, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	mlkemBytes, err := orig.MLKEMPrivate.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal mlkem private key: %v", err)
	}

	stored := storedKeyPair{
		X25519Private: base64.StdEncoding.EncodeToString(orig.X25519Private.Bytes()),
		MLKEMPrivate:  base64.StdEncoding.EncodeToString(mlkemBytes),
	}
	jsonData, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("failed to marshal stored key: %v", err)
	}

	k, source, err := LoadOrGenerateKeyPair("/non/existent/path/key.json", string(jsonData))
	if err != nil {
		t.Fatalf("failed to load key from env JSON: %v", err)
	}
	if source != "environment variable (MLKEM_KEY_JSON)" {
		t.Fatalf("unexpected source: %s", source)
	}
	if k == nil {
		t.Fatalf("keypair should not be nil")
	}

	origPub, _ := orig.MLKEMPublicKeyBytes()
	loadedPub, _ := k.MLKEMPublicKeyBytes()
	if string(origPub) != string(loadedPub) {
		t.Fatalf("public key mismatch from env JSON")
	}
}

func TestSaveAndLoadKeyPairFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test_key.key")

	kOrig, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	if err := SaveKeyPair(kOrig, keyFile); err != nil {
		t.Fatalf("failed to save keypair: %v", err)
	}

	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("key file was not created: %v", err)
	}

	kLoaded, err := LoadKeyPair(keyFile)
	if err != nil {
		t.Fatalf("failed to load keypair: %v", err)
	}

	origPub, _ := kOrig.MLKEMPublicKeyBytes()
	loadedPub, _ := kLoaded.MLKEMPublicKeyBytes()
	if string(origPub) != string(loadedPub) {
		t.Fatalf("saved and loaded MLKEM public keys do not match")
	}
}
