package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/httpapi"
	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
	"github.com/kelvin/kelvin/packages/common/logging"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"go.uber.org/zap"
)

type principalCtxKey struct{}

// ContextWithPrincipal binds the authenticated Principal to the request context.
func ContextWithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, p)
}

// PrincipalFromContext extracts the authenticated Principal from context, if present.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(*Principal)
	return p, ok && p != nil
}

// Middleware creates an HTTP authentication middleware using the provided TokenService.
func Middleware(tokenService *TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httpapi.WriteProblem(w, r, kelvinerrors.NewUnauthenticated("missing authorization header"))
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				httpapi.WriteProblem(w, r, kelvinerrors.NewUnauthenticated("authorization header must be in Bearer token format"))
				return
			}

			tokenStr := strings.TrimSpace(parts[1])
			principal, err := tokenService.VerifyAccessToken(tokenStr)
			if err != nil {
				logging.FromContext(r.Context()).Warn("token verification failed", zap.Error(err))
				httpapi.WriteProblem(w, r, kelvinerrors.NewUnauthenticated("invalid or expired token"))
				return
			}

			// Add correlation and principal info to request context
			ctx := ContextWithPrincipal(r.Context(), principal)
			ctx, err = tenant.WithID(ctx, principal.TenantID)
			if err != nil {
				httpapi.WriteProblem(w, r, kelvinerrors.NewUnauthenticated("token has no valid tenant context"))
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole checks that the request principal possesses one of the required roles.
func RequireRole(allowedRoles ...Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := PrincipalFromContext(r.Context())
			if !ok {
				httpapi.WriteProblem(w, r, kelvinerrors.NewUnauthenticated("authentication required"))
				return
			}

			for _, role := range allowedRoles {
				if principal.Role == role {
					next.ServeHTTP(w, r)
					return
				}
			}

			logging.FromContext(r.Context()).Warn("forbidden: insufficient role",
				zap.String("user_id", principal.UserID.String()),
				zap.String("user_role", string(principal.Role)),
			)
			httpapi.WriteProblem(w, r, kelvinerrors.NewForbidden("insufficient permissions for this resource"))
		})
	}
}

// TenantGuard verifies that the request principal matches the expected tenant context.
// Prevents Broken Object Level Authorization (BOLA/IDOR).
func TenantGuard(expectedTenantID uuid.UUID) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := PrincipalFromContext(r.Context())
			if !ok {
				httpapi.WriteProblem(w, r, kelvinerrors.NewUnauthenticated("authentication required"))
				return
			}

			if principal.TenantID != expectedTenantID {
				logging.FromContext(r.Context()).Warn("cross-tenant access attempt blocked (IDOR)",
					zap.String("principal_tenant", principal.TenantID.String()),
					zap.String("target_tenant", expectedTenantID.String()),
					zap.String("user_id", principal.UserID.String()),
				)
				// Return 403 Forbidden with audit-safe envelope
				httpapi.WriteProblem(w, r, kelvinerrors.NewForbidden("access to the requested tenant resource is forbidden"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
