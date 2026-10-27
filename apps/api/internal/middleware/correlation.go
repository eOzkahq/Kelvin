package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/kelvin/kelvin/packages/common/logging"
	"github.com/kelvin/kelvin/packages/common/validation"
	"go.uber.org/zap"
)

// CorrelationHeader is the Kelvin request-tracing header (API_STANDARDS §10.1).
const CorrelationHeader = "X-Correlation-ID"

// Correlation validates or generates the request correlation ID, attaches it to
// the context (and thus to every subsequent log line), and echoes it on the
// response. Invalid client values are discarded with a WARN, never rejected.
func Correlation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(CorrelationHeader)
		switch {
		case id == "":
			id = newID()
		case !validation.IsCorrelationID(id):
			logging.FromContext(r.Context()).Warn("invalid correlation id discarded",
				zap.String("client_value", truncate(id, 128)))
			id = newID()
		}
		w.Header().Set(CorrelationHeader, id)
		next.ServeHTTP(w, r.WithContext(logging.WithCorrelation(r.Context(), id)))
	})
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	dst := make([]byte, 36)
	hex.Encode(dst[0:8], b[0:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], b[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], b[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], b[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:36], b[10:16])
	return string(dst)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
