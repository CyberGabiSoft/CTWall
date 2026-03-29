package middleware

import (
	"mime"
	"net/http"
	"strings"
)

// RequireJSONContentType enforces application/json for requests with a body.
func RequireJSONContentType() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength == 0 && strings.TrimSpace(r.Header.Get("Content-Type")) == "" {
				next(w, r)
				return
			}
			contentType := r.Header.Get("Content-Type")
			mediaType, _, err := mime.ParseMediaType(contentType)
			if err != nil || !strings.EqualFold(mediaType, "application/json") {
				writeProblem(w, r, http.StatusUnsupportedMediaType, "Unsupported Media Type", "Content-Type must be application/json.")
				return
			}
			next(w, r)
		}
	}
}
