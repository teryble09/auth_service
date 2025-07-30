package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/teryble09/auth_service/app/dto"
	"github.com/teryble09/auth_service/app/model"
	"github.com/teryble09/auth_service/app/pkg/access_token"
	"github.com/teryble09/auth_service/app/pkg/refresh_token"
	"github.com/teryble09/auth_service/app/storage"
)

type AuthService struct {
	Logger        *slog.Logger
	DB            Repository
	TokenLivetime time.Duration
	Secret        string
	WebhookAdress string
	BlackList     *cache.Cache
}

func (srv *AuthService) NewSession(req dto.NewSessionRequest) (resp dto.NewSessionResponse, err error) {
	session := model.Session{}
	session.UserGUID = req.UserGUID
	session.IP = req.IP
	session.UserAgent = req.UserAgent

	refreshToken, hashedRToken := refresh_token.MustCreateNew()
	session.RefreshTokenHash = hashedRToken

	sessionID, err := srv.DB.CreateNewSession(session)

	if err != nil {
		srv.Logger.Error("Could not create session", "error", err.Error())
		return dto.NewSessionResponse{}, err
	}

	sighnedToken, err := access_token.Generate(sessionID, []byte(srv.Secret), srv.TokenLivetime)

	if err != nil {
		srv.Logger.Error("Could not create access token", "SessionID", sessionID, "error", err.Error())
		return dto.NewSessionResponse{}, err
	}

	resp.AccessToken = sighnedToken
	resp.RefreshToken = refreshToken

	return resp, nil
}

func (srv *AuthService) GetUserGuid(req dto.GetUserGuidRequest) (dto.GetUserGuidResponse, error) {
	guid, err := srv.DB.GetUserGuid(req.SessionID)
	if err == storage.ErrSessionNotExist {
		srv.Logger.Error("Trying to get user guid by sessionID but session does not exist", "sessionID", req.SessionID)
	}
	return dto.GetUserGuidResponse{UserGUID: guid}, err
}

var ErrUserAgentChange = errors.New("user agent changed")
var ErrWrongRefreshToken = errors.New("refresh tokens does not match")

func (srv *AuthService) RefreshPair(req dto.RefreshPairRequest) (dto.RefreshPairResponse, error) {
	session, err := srv.DB.GetSession(req.SessionID)
	if err != nil {
		srv.Logger.Error("Could not get session", "error", err.Error())
		return dto.RefreshPairResponse{}, err
	}

	if refresh_token.Compare(req.RefreshToken, session.RefreshTokenHash) {
		srv.Logger.Warn("Trying to refresh with a wrong refresh token", "old", session.RefreshTokenHash, "new", refresh_token.MustHashToken(req.RefreshToken))
		return dto.RefreshPairResponse{}, ErrWrongRefreshToken
	}

	if session.UserAgent != req.UserAgent {
		deactivate := dto.DeactivateSessionRequest{
			AccessToken: req.AccessToken,
			SessionID:   req.SessionID,
		}
		srv.DeactivateSession(deactivate)
		srv.Logger.Warn("User agent changed ", "sessionID", req.SessionID)
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

	refreshToken, hashRefreshToken := refresh_token.MustCreateNew()

	err = srv.DB.RefreshSession(req.SessionID, req.IP, hashRefreshToken)
	if err != nil {
		srv.Logger.Error("Could not refresh session", "error", err.Error())
		return dto.RefreshPairResponse{}, err
	}

	accessToken, err := access_token.Generate(req.SessionID, []byte(srv.Secret), srv.TokenLivetime)
	if err != nil {
		srv.Logger.Error("Could not generate new token", "error", err.Error())
		return dto.RefreshPairResponse{}, err
	}

	srv.BlackList.Set(req.AccessToken, true, srv.TokenLivetime)

	return dto.RefreshPairResponse{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (srv *AuthService) DeactivateSession(req dto.DeactivateSessionRequest) error {
	srv.BlackList.Set(req.AccessToken, true, srv.TokenLivetime)

	err := srv.DB.DeleteSession(req.SessionID)
	if err != nil {
		srv.Logger.Error("Could not delete session", "error", err.Error())
		return err
	}

	return nil
}
