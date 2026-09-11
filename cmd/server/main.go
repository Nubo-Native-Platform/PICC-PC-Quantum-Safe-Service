// Command server starts the quantum-safe crypto HTTP service.
package main

import (
	"log"

	"github.com/gin-gonic/gin"

	"nnp-quantum-safe-service/internal/config"
	"nnp-quantum-safe-service/internal/handlers"
	"nnp-quantum-safe-service/internal/pqcrypto"
	"nnp-quantum-safe-service/internal/routes"
)

func main() {
	cfg := config.Load()
	gin.SetMode(cfg.GinMode)

	keys, source, err := pqcrypto.LoadOrGenerateKeyPair(cfg.KeyPath, cfg.KeyJSON)
	if err != nil {
		log.Fatalf("failed to load hybrid keypair: %v", err)
	}

	mlkemPubBytes, _ := keys.MLKEMPublicKeyBytes()
	log.Printf("Using persistent hybrid keypair (X25519 + ML-KEM-768) from %s (mlkem public key: %d bytes)", source, len(mlkemPubBytes))

	h := handlers.NewHandler(keys)
	router := routes.New(h)

	log.Printf("Quantum-safe crypto service listening on :%s", cfg.Port)
	log.Printf("Routes: POST /encrypt  POST /decrypt  GET /public-key  GET /health")
	if err := router.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}

}
