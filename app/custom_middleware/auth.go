package custom_middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/patrickmn/go-cache"
	"github.com/teryble09/auth_service/app/pkg/access_token"
)

func NewVerifyToken(secret string, blacklist *cache.Cache) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Missing authorization header", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Invalid authorization format", http.StatusBadRequest)
				return
			}

			accessToken := parts[1]

			_, found := blacklist.Get(accessToken)

			if found {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			claims, err := access_token.VerifyAndGetClaims(accessToken, []byte(secret))

			if err != nil {
				http.Error(w, "Token is invalid", http.StatusUnauthorized)
				return
			}

			r = r.WithContext(context.WithValue(r.Context(), "SessionID", claims.SessionID))

			next.ServeHTTP(w, r)
		})
	}
}
