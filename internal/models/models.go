// Package models holds the HTTP request/response DTOs for the crypto
// service, kept separate from the handlers that use them so the wire
// format can be reviewed, versioned, or reused (e.g. by tests or a client
// SDK) independently of routing/handler logic.
package models

// ---- /public-key ----

// PublicKeyResponse is returned by GET /public-key.
type PublicKeyResponse struct {
	Algorithm    string `json:"algorithm"`
	MLKEMPublic  string `json:"mlkem_public_key"`  // base64, ML-KEM-768
	X25519Public string `json:"x25519_public_key"` // base64, 32 bytes
}

// ---- /encrypt ----

// EncryptRequest is the body for POST /encrypt.
type EncryptRequest struct {
	Plaintext string `json:"plaintext" binding:"required"`
}

// EncryptResponse is returned by POST /encrypt. Send these fields back to
// POST /decrypt to recover the plaintext.
type EncryptResponse struct {
	Algorithm             string `json:"algorithm"`
	KEMCiphertext         string `json:"kem_ciphertext"`          // base64, ML-KEM-768
	X25519EphemeralPublic string `json:"x25519_ephemeral_public"` // base64, sender's ephemeral X25519 public key
	Nonce                 string `json:"nonce"`                   // base64
	Ciphertext            string `json:"ciphertext"`              // base64
}

// ---- /decrypt ----

// DecryptRequest is the body for POST /decrypt — the fields returned by a
// prior POST /encrypt call.
type DecryptRequest struct {
	KEMCiphertext         string `json:"kem_ciphertext" binding:"required"`
	X25519EphemeralPublic string `json:"x25519_ephemeral_public" binding:"required"`
	Nonce                 string `json:"nonce" binding:"required"`
	Ciphertext            string `json:"ciphertext" binding:"required"`
}

// DecryptResponse is returned by POST /decrypt.
type DecryptResponse struct {
	Plaintext string `json:"plaintext"`
}

// ---- /health ----

// HealthResponse is returned by GET /health.
type HealthResponse struct {
	Status string `json:"status"`
}

// ---- errors ----

// ErrorResponse is the shape returned for any 4xx/5xx response.
type ErrorResponse struct {
	Error string `json:"error"`
}
