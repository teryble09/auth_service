package service

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"time"

	"github.com/teryble09/auth_service/app/dto"
	"github.com/teryble09/auth_service/app/model"
	"github.com/teryble09/auth_service/app/token"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	Logger        *slog.Logger
	DB            Repository
	TokenLivetime time.Duration
	Secret        string
}

func (srv *AuthService) NewSession(req dto.NewSessionRequest) (resp dto.NewSessionResponse, err error) {
	session := model.Session{}
	session.UserGUID = req.UserGUID
	session.IP = req.IP
	session.UserAgent = req.UserAgent

	refreshToken := base64.RawURLEncoding.EncodeToString([]byte(rand.Text()))

	hashedRToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		srv.Logger.Error("Could not hash", "token", refreshToken, "error", err.Error())
		return dto.NewSessionResponse{}, err
	}

	session.RefreshTokenHash = string(hashedRToken)

	sessionID, err := srv.DB.CreateNewSession(session)
	if err != nil {
		srv.Logger.Error("Could not save session to db", "error", err.Error())
		return dto.NewSessionResponse{}, err
	}

	sighnedToken, err := token.Generate(sessionID, []byte(srv.Secret), time.Now().Add(srv.TokenLivetime))
	if err != nil {
		return dto.NewSessionResponse{}, err
	}

	resp.AccessToken = sighnedToken
	resp.RefreshToken = refreshToken

	return resp, nil
}

func (srv *AuthService) GetUserGuid(req dto.GetUserGuidRequest) (dto.GetUserGuidResponse, error) {
	guid, err := srv.DB.GetUserGuid(req.SessionID)
	return dto.GetUserGuidResponse{UserGUID: guid}, err
}
