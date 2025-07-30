package refresh_token

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
)

func MustCreateNew() (refresh string, hash string) {
	refreshToken := base64.RawURLEncoding.EncodeToString([]byte(rand.Text()))
	return refreshToken, MustHashToken(refreshToken)
}

func MustHashToken(token string) string {
	hashedRToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		panic("Could not hash token, check algorythm: token " + token + " error " + err.Error())
	}
	return string(hashedRToken)
}

func Compare(refresh string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(refresh))
	if err != nil {
		return true
	}
	return false
}
