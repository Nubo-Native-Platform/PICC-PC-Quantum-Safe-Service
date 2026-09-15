// Package handlers contains the Gin handler functions for the quantum-safe
// crypto service. Request/response shapes live in internal/models; routes
// live in internal/routes. Handlers depend only on internal/models and
// internal/pqcrypto (not on Gin globals), so they're easy to unit test
// with httptest.
package handlers

import (
	"encoding/base64"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"nnp-quantum-safe-service/internal/models"
	"nnp-quantum-safe-service/internal/pqcrypto"
)

// Handler bundles the dependencies HTTP handlers need (currently just the
// server's ML-KEM keypair). Constructed once in main and wired into the router.
type Handler struct {
	Keys *pqcrypto.KeyPair
}

// NewHandler creates a Handler backed by the given keypair.
func NewHandler(keys *pqcrypto.KeyPair) *Handler {
	return &Handler{Keys: keys}
}

// Health handles GET /health.
func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, models.HealthResponse{Status: "ok"})
}

// PublicKey handles GET /public-key.
func (h *Handler) PublicKey(c *gin.Context) {
	mlkemBytes, err := h.Keys.MLKEMPublicKeyBytes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "failed to marshal ML-KEM public key"})
		return
	}
	c.JSON(http.StatusOK, models.PublicKeyResponse{
		Algorithm:    "Hybrid: X25519 + ML-KEM-768",
		MLKEMPublic:  base64.StdEncoding.EncodeToString(mlkemBytes),
		X25519Public: base64.StdEncoding.EncodeToString(h.Keys.X25519PublicKeyBytes()),
	})
}

// Encrypt handles POST /encrypt.
func (h *Handler) Encrypt(c *gin.Context) {
	var req models.EncryptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid request: " + err.Error()})
		return
	}

	result, err := pqcrypto.Encrypt(h.Keys.MLKEMPublic, h.Keys.X25519Public, []byte(req.Plaintext))
	if err != nil {
		log.Printf("encrypt error: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "encryption failed"})
		return
	}

	c.JSON(http.StatusOK, models.EncryptResponse{
		Algorithm:             "Hybrid: X25519 + ML-KEM-768 + HKDF-SHA256 + AES-256-GCM",
		KEMCiphertext:         base64.StdEncoding.EncodeToString(result.KEMCiphertext),
		X25519EphemeralPublic: base64.StdEncoding.EncodeToString(result.X25519EphemeralPublic),
		Nonce:                 base64.StdEncoding.EncodeToString(result.Nonce),
		Ciphertext:            base64.StdEncoding.EncodeToString(result.Ciphertext),
	})
}

// Decrypt handles POST /decrypt.
func (h *Handler) Decrypt(c *gin.Context) {
	var req models.DecryptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid request: " + err.Error()})
		return
	}

	kemCT, err := base64.StdEncoding.DecodeString(req.KEMCiphertext)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid base64 in kem_ciphertext"})
		return
	}
	x25519EphPub, err := base64.StdEncoding.DecodeString(req.X25519EphemeralPublic)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid base64 in x25519_ephemeral_public"})
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid base64 in nonce"})
		return
	}
	ciphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid base64 in ciphertext"})
		return
	}

	plaintext, err := pqcrypto.Decrypt(h.Keys.MLKEMPrivate, h.Keys.X25519Private, kemCT, x25519EphPub, nonce, ciphertext)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.DecryptResponse{Plaintext: string(plaintext)})
}
