// Package docs embeds the OpenAPI 3.0 spec for the service and exposes
// handlers to serve the raw spec and a Swagger UI page that renders it,
// so API documentation ships with the binary — no separate doc site to
// keep in sync.
package docs

import (
	_ "embed"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed openapi.yaml
var openAPISpec []byte

// Spec handles GET /openapi.yaml — returns the raw OpenAPI 3.0 document.
func Spec(c *gin.Context) {
	c.Data(http.StatusOK, "application/yaml", openAPISpec)
}

// swaggerUIPage renders Swagger UI (via CDN) pointed at /openapi.yaml.
// No server-side templating needed: the JS fetches the spec itself.
const swaggerUIPage = `<!DOCTYPE html>
<html>
<head>
  <title>NNP Quantum-Safe Service — API Docs</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body style="margin:0">
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: "/openapi.yaml",
        dom_id: "#swagger-ui",
      });
    };
  </script>
</body>
</html>`

// UI handles GET /docs — an interactive Swagger UI for the API.
func UI(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(swaggerUIPage))
}
