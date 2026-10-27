package middleware

import (
	"net/http"
	"time"

	"github.com/kelvin/kelvin/packages/common/logging"
	"go.uber.org/zap"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
	size   int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.size += n
	return n, err
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// AccessLog emits one structured line per request: method, path, status,
// duration, correlation ID. Never bodies, never secrets (API_STANDARDS §12.1).
func AccessLog() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}
			logging.FromContext(r.Context()).Info("request",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", status),
				zap.Int("bytes", rec.size),
				zap.Duration("duration", time.Since(start)),
			)
		})
	}
}
