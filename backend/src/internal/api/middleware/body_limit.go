package middleware

import "net/http"

const DefaultJSONBodyLimit int64 = 256 << 10

// WithBodyLimit wraps a handler to cap request body size.
func WithBodyLimit(limit int64) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if limit > 0 {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next(w, r)
		}
	}
}
