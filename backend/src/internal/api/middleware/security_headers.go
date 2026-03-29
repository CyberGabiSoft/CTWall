package middleware

import (
	"net/http"
	"strings"
)

const apiCSP = "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"

// WithSecurityHeaders injects security-focused response headers.
func WithSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secured := &securityHeaderWriter{
			ResponseWriter: w,
			request:        r,
		}
		next.ServeHTTP(secured, r)
	})
}

type securityHeaderWriter struct {
	http.ResponseWriter
	request     *http.Request
	wroteHeader bool
}

func (s *securityHeaderWriter) WriteHeader(status int) {
	s.apply()
	s.ResponseWriter.WriteHeader(status)
}

func (s *securityHeaderWriter) Write(payload []byte) (int, error) {
	s.apply()
	return s.ResponseWriter.Write(payload)
}

func (s *securityHeaderWriter) apply() {
	if s.wroteHeader {
		return
	}
	s.wroteHeader = true
	setSecurityHeaders(s.ResponseWriter, s.request)
}

func setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	if r == nil {
		return
	}
	header := w.Header()
	if isSecureRequest(r) {
		header.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
	// Allow handlers (e.g. Swagger UI) to override CSP before headers are written.
	if header.Get("Content-Security-Policy") == "" {
		header.Set("Content-Security-Policy", apiCSP)
	}
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	// Defense-in-depth (CSP frame-ancestors is preferred, but XFO helps older clients).
	header.Set("X-Frame-Options", "DENY")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-site")
	header.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), interest-cohort=()")
	if strings.HasPrefix(r.URL.Path, "/api/") {
		header.Set("Cache-Control", "no-store")
	}
}

func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Ssl")), "on") {
		return true
	}
	return false
}
