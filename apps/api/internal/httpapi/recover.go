package httpapi

import (
	"fmt"
	"net/http"
	"runtime/debug"

	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
	"github.com/kelvin/kelvin/packages/common/logging"
	"go.uber.org/zap"
)

// Recover converts panics into sanitized RFC 7807 internal_error responses
// (API_STANDARDS §12.1, §7.3): the full stack goes to the logs with the
// correlation ID; the client receives only the generic problem object.
// It is registered inside the access log so the logged status is the 500 the
// client actually received.
func Recover() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				logging.FromContext(r.Context()).Error("panic recovered",
					zap.Any("panic", rec),
					zap.ByteString("stack", debug.Stack()),
				)
				WriteProblem(w, r, kelvinerrors.NewInternal(fmt.Errorf("panic: %v", rec)))
			}()
			next.ServeHTTP(w, r)
		})
	}
}
