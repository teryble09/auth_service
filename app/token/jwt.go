package token

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

func Generate(sessionID int64, secret []byte, expiresAt time.Time) (string, error) {
	claims := SessionClaims{
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),  // Время истечения
			IssuedAt:  jwt.NewNumericDate(time.Now()), // Текущее время
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	return token.SignedString(secret)
}

func GetClaimsFrom(tokenString string, secret []byte) (*SessionClaims, error) {
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

func GetSessionIDFrom(tokenString string, secret []byte) (sessionID int64, err error) {
	claims, err := GetClaimsFrom(tokenString, secret)
	if err != nil {
		return 0, err
	}
	return claims.SessionID, nil
}

func Verify(tokenString string, secret []byte) error {
	claims, err := GetClaimsFrom(tokenString, secret)
	if err != nil {
		return err
	}
	switch time.Now().Compare(claims.ExpiresAt.Time) {
	case -1:
		return nil
	case 0:
		return nil
	case 1:
		return ErrTokenExpired
	}
	return nil
}
