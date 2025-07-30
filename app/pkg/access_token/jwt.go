package access_token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrTokenExpired = errors.New("token expired")
	ErrTokenInvalid = errors.New("token is invalid")
)

type SessionClaims struct {
	SessionID int64 `json:"session_id"`
	jwt.RegisteredClaims
}

func Generate(sessionID int64, secret []byte, livetyme time.Duration) (string, error) {
	claims := SessionClaims{
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(livetyme)), // Время истечения
			IssuedAt:  jwt.NewNumericDate(time.Now()),               // Текущее время
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	return token.SignedString(secret)
}

func getClaimsFrom(tokenString string, secret []byte) (*SessionClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&SessionClaims{},
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrTokenInvalid
			}
			return secret, nil
		},
	)

	if err != nil {
		return nil, ErrTokenInvalid
	}

	if claims, ok := token.Claims.(*SessionClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrTokenInvalid
}

func VerifyAndGetClaims(tokenString string, secret []byte) (*SessionClaims, error) {
	claims, err := getClaimsFrom(tokenString, secret)
	if err != nil {
		return nil, err
	}
	switch time.Now().Compare(claims.ExpiresAt.Time) {
	case -1:
		return claims, nil
	case 0:
		return claims, nil
	case 1:
		return nil, ErrTokenExpired
	default:
		return claims, nil
	}
}
