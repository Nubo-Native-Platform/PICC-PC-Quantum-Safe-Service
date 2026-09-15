// Package routes owns the Gin engine and the route table for the
// quantum-safe crypto service. It knows about internal/handlers (to wire
// each path to its handler function) but contains no handler logic itself.
package routes

import (
	"github.com/gin-gonic/gin"

	"nnp-quantum-safe-service/internal/docs"
	"nnp-quantum-safe-service/internal/handlers"
)

// New builds the Gin engine and registers all routes against h.
func New(h *handlers.Handler) *gin.Engine {
	router := gin.Default()

	router.GET("/health", h.Health)
	router.GET("/public-key", h.PublicKey)
	router.POST("/encrypt", h.Encrypt)
	router.POST("/decrypt", h.Decrypt)

	router.GET("/openapi.yaml", docs.Spec)
	router.GET("/docs", docs.UI)

	return router
}
