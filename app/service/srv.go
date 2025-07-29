package service

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
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
	WebhookAdress string
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

var ErrUserAgentChange = errors.New("user agent changed")

func (srv *AuthService) RefreshPair(req dto.RefreshPairRequest) (dto.RefreshPairResponse, error) {
	sessionID, err := token.GetSessionIDFrom(req.AccessToken, []byte(srv.Secret))
	if err != nil {
		return dto.RefreshPairResponse{}, err
	}

	session, err := srv.DB.GetSession(sessionID)
	if err != nil {
		return dto.RefreshPairResponse{}, err
	}

	if session.UserAgent != req.UserAgent {
		deactivate := dto.DeactivateSessionRequest{
			AccessToken: req.AccessToken,
		}
		srv.DeactivateSession(deactivate)
		return dto.RefreshPairResponse{}, ErrUserAgentChange
	}

	if session.IP != req.IP {
		mes := dto.WebhookPostMessage{
			UserGUID: session.UserGUID,
			OldIP:    session.IP,
			NewIP:    req.IP,
			Time:     time.Now(),
		}
		buf := bytes.NewBuffer([]byte{})
		json.NewEncoder(buf).Encode(mes)
		_, err := http.Post(srv.WebhookAdress, "application/json", buf)
		if err != nil {
			srv.Logger.Error("Could not send message to webhook", "error", err.Error())
		}
	}

	refreshToken := base64.RawURLEncoding.EncodeToString([]byte(rand.Text()))
	hashedRToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		srv.Logger.Error("Could not hash", "token", refreshToken, "error", err.Error())
		return dto.RefreshPairResponse{}, err
	}

	err = srv.DB.RefreshSession(sessionID, req.IP, string(hashedRToken))
	if err != nil {
		srv.Logger.Error("Could not save new refresh token", "error", err.Error())
		return dto.RefreshPairResponse{}, err
	}

	accessToken, err := token.Generate(sessionID, []byte(srv.Secret), time.Now().Add(srv.TokenLivetime))
	if err != nil {
		srv.Logger.Error("Could not generate new token", "error", err.Error())
		return dto.RefreshPairResponse{}, err
	}

	return dto.RefreshPairResponse{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (srv *AuthService) DeactivateSession(req dto.DeactivateSessionRequest) error {
	sessionID, err := token.GetSessionIDFrom(req.AccessToken, []byte(srv.Secret))
	if err != nil {
		return err
	}

	err = srv.DB.DeleteSession(sessionID)
	if err != nil {
		return err
	}

	return nil
}
