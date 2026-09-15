package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"nnp-quantum-safe-service/internal/models"
	"nnp-quantum-safe-service/internal/pqcrypto"
)

func setupTestRouter() (*gin.Engine, *Handler) {
	gin.SetMode(gin.TestMode)
	keys, _, _ := pqcrypto.LoadOrGenerateKeyPair("")
	h := NewHandler(keys)

	r := gin.New()
	r.GET("/health", h.Health)
	r.GET("/public-key", h.PublicKey)
	r.POST("/encrypt", h.Encrypt)
	r.POST("/decrypt", h.Decrypt)

	return r, h
}

func TestHealthHandler(t *testing.T) {
	r, _ := setupTestRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/health", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	r, _ := setupTestRouter()

	// 1. Get Public Key
	wPub := httptest.NewRecorder()
	reqPub, _ := http.NewRequest(http.MethodGet, "/public-key", nil)
	r.ServeHTTP(wPub, reqPub)
	if wPub.Code != http.StatusOK {
		t.Fatalf("expected 200 for public key, got %d", wPub.Code)
	}

	var pubResp models.PublicKeyResponse
	if err := json.Unmarshal(wPub.Body.Bytes(), &pubResp); err != nil {
		t.Fatalf("failed to decode public key: %v", err)
	}
	if pubResp.MLKEMPublic == "" || pubResp.X25519Public == "" {
		t.Fatalf("public keys should not be empty")
	}

	// 2. Encrypt
	plainMessage := "Test quantum-safe secret message 12345"
	encBody, _ := json.Marshal(models.EncryptRequest{Plaintext: plainMessage})
	wEnc := httptest.NewRecorder()
	reqEnc, _ := http.NewRequest(http.MethodPost, "/encrypt", bytes.NewBuffer(encBody))
	reqEnc.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(wEnc, reqEnc)

	if wEnc.Code != http.StatusOK {
		t.Fatalf("expected 200 for encrypt, got %d: %s", wEnc.Code, wEnc.Body.String())
	}

	var encResp models.EncryptResponse
	if err := json.Unmarshal(wEnc.Body.Bytes(), &encResp); err != nil {
		t.Fatalf("failed to decode encrypt response: %v", err)
	}

	// 3. Decrypt
	decBody, _ := json.Marshal(models.DecryptRequest{
		KEMCiphertext:         encResp.KEMCiphertext,
		X25519EphemeralPublic: encResp.X25519EphemeralPublic,
		Nonce:                 encResp.Nonce,
		Ciphertext:            encResp.Ciphertext,
	})
	wDec := httptest.NewRecorder()
	reqDec, _ := http.NewRequest(http.MethodPost, "/decrypt", bytes.NewBuffer(decBody))
	reqDec.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(wDec, reqDec)

	if wDec.Code != http.StatusOK {
		t.Fatalf("expected 200 for decrypt, got %d: %s", wDec.Code, wDec.Body.String())
	}

	var decResp models.DecryptResponse
	if err := json.Unmarshal(wDec.Body.Bytes(), &decResp); err != nil {
		t.Fatalf("failed to decode decrypt response: %v", err)
	}

	if decResp.Plaintext != plainMessage {
		t.Fatalf("decrypted text mismatch: got %q, want %q", decResp.Plaintext, plainMessage)
	}
}
