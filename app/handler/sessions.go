package handler

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/teryble09/auth_service/app/dto"
	"github.com/teryble09/auth_service/app/service"
)

func NewSession(srv *service.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		req := dto.NewSessionRequest{}
		err := json.NewDecoder(r.Body).Decode(&req)
		if (err != nil || req.UserGUID == uuid.UUID{}) {
			http.Error(w, "Request is invalid", http.StatusBadRequest)
			return
		}

		req.IP, _, _ = net.SplitHostPort(r.RemoteAddr)
		req.UserAgent = r.UserAgent()

		resp, err := srv.NewSession(req)
		if err != nil {
			http.Error(w, "Could not create new session", http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "application-json")
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			srv.Logger.Error("Could not create json response", "error", err.Error())
			return
		}
	}
}

func RefreshToken(srv *service.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		req := dto.RefreshPairRequest{}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil || req.RefreshToken == "" {
			http.Error(w, "Request is invalid", http.StatusBadRequest)
			return
		}

		req.SessionID = r.Context().Value("SessionID").(int64)
		req.AccessToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		req.IP, _, _ = net.SplitHostPort(r.RemoteAddr)
		req.UserAgent = r.UserAgent()

		resp, err := srv.RefreshPair(req)
		if err != nil {
			if err == service.ErrUserAgentChange {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			if err == service.ErrWrongRefreshToken {
				http.Error(w, "Wrong refresh token", http.StatusBadRequest)
				return
			}
			http.Error(w, "Internal", http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "application-json")
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			srv.Logger.Error("Could not create json response", "error", err.Error())
			return
		}
	}
}

func GetUserGuid(srv *service.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		sessionID := r.Context().Value("SessionID").(int64)

		resp, err := srv.GetUserGuid(dto.GetUserGuidRequest{SessionID: sessionID})
		if err != nil {
			http.Error(w, "Internal", http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "application-json")
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			srv.Logger.Error("Could not create json response", "error", err.Error())
			return
		}
	}
}

func DeactivateSession(srv *service.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		sessionID := r.Context().Value("SessionID").(int64)
		accessToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		err := srv.DeactivateSession(dto.DeactivateSessionRequest{SessionID: sessionID, AccessToken: accessToken})
		if err != nil {
			http.Error(w, "Internal", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}
