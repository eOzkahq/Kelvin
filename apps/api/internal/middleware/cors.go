package middleware

import (
	"net/http"
	"strings"
)

// CORS returns a middleware enforcing strict allowlisted origins.
// Wildcards (*) are strictly prohibited.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	originsMap := make(map[string]bool)
	for _, o := range allowedOrigins {
		o = strings.TrimSpace(o)
		if o != "" && o != "*" {
			originsMap[o] = true
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				// Non-CORS request (same-origin, curl, server-to-server)
				next.ServeHTTP(w, r)
				return
			}

			// Reject origins not present in the allowlist
			if !originsMap[origin] {
				if r.Method == http.MethodOptions {
					http.Error(w, "Forbidden: CORS origin not allowlisted", http.StatusForbidden)
					return
				}
				// For non-OPTIONS requests, continue without Access-Control-Allow-Origin
				// so the browser security model blocks cross-origin reading.
				next.ServeHTTP(w, r)
				return
			}

			// Set authorized CORS response headers
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Idempotency-Key, X-Idempotency-Key, X-Request-ID, X-Correlation-ID, X-Requested-With")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.Header().Add("Vary", "Origin")

			// Handle preflight OPTIONS request
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
