package custom_middleware

import (
	"net/http"
	"strings"

	"github.com/teryble09/auth_service/app/token"
)

// это очень неправильно, насколько я понял, только учусь xd,возможно стоило создать фабрику
func VerifyToken(next http.Handler, secret string) http.HandlerFunc {
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

		if err := token.Verify(accessToken, []byte(secret)); err != nil {
			switch err {
			case token.ErrTokenExpired:
				http.Error(w, "Token expired", http.StatusUnauthorized)
				return
			case token.ErrTokenInvalid:
				http.Error(w, "Token is invalid", http.StatusUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
