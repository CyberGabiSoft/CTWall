package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

var openAPICache struct {
	once sync.Once
	data []byte
	err  error
}

// OpenAPIHandler serves the OpenAPI specification as YAML.
func OpenAPIHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := loadOpenAPI()
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load OpenAPI spec.", err)
			return
		}
		w.Header().Set("Content-Type", "application/openapi+yaml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}
}

// DocsHandler serves the Swagger UI page.
func DocsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, err := docsNonce()
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to initialize docs.", err)
			return
		}
		// Swagger UI requires an inline init script. Use a nonce to avoid 'unsafe-inline'.
		w.Header().Set("Content-Security-Policy", fmt.Sprintf(swaggerCSPTemplate, nonce))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(swaggerHTMLTemplate, nonce)))
	}
}

func loadOpenAPI() ([]byte, error) {
	openAPICache.once.Do(func() {
		paths := []string{
			filepath.Join("api", "openapi.yaml"),
		}

		if exe, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exe)
			paths = append(paths,
				filepath.Join(exeDir, "api", "openapi.yaml"),
				filepath.Join(exeDir, "..", "api", "openapi.yaml"),
			)
		}

		for _, path := range paths {
			if data, err := os.ReadFile(path); err == nil {
				openAPICache.data = data
				return
			} else {
				openAPICache.err = err
			}
		}
	})
	return openAPICache.data, openAPICache.err
}

var docsNonce = func() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(buf), nil
}

const swaggerCSPTemplate = "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; " +
	"script-src 'self' https://unpkg.com 'nonce-%s'; style-src 'self' https://unpkg.com; " +
	"img-src 'self' data:; font-src https://unpkg.com; connect-src 'self'"

const swaggerHTMLTemplate = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>CTWall API Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
    <script nonce="%s">
      window.onload = function () {
        window.ui = SwaggerUIBundle({
          url: "/api/v1/openapi.yaml",
          dom_id: "#swagger-ui",
          layout: "BaseLayout",
          deepLinking: true
        });
      };
    </script>
  </body>
</html>`
