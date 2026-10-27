package middleware

import "net/http"

// BodyLimit caps request bodies at the gateway default of 1 MiB
// (API_STANDARDS §5.2). Oversized reads surface as *http.MaxBytesError and are
// mapped to 413 payload_too_large by httpapi.DecodeJSON.
func BodyLimit(bytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, bytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}
