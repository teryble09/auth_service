package handler

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/teryble09/auth_service/app/dto"
	"github.com/teryble09/auth_service/app/service"
	"github.com/teryble09/auth_service/app/storage"
	"github.com/teryble09/auth_service/app/token"
)

func NewSession(srv *service.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		req := dto.NewSessionRequest{}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
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
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

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

		req.AccessToken = parts[1]
		req.UserAgent = r.UserAgent()
		req.IP, _, _ = net.SplitHostPort(r.RemoteAddr)

		resp, err := srv.RefreshPair(req)
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

		sessionID, err := token.GetSessionIDFrom(accessToken, []byte(srv.Secret))
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		resp, err := srv.GetUserGuid(dto.GetUserGuidRequest{SessionID: sessionID})
		if err == storage.ErrSessionNotExist {
			http.Error(w, "Session does not exist", http.StatusBadRequest)
			srv.Logger.Error("Session does not exist", "token", accessToken)
			return
		}
		if err != nil {
			http.Error(w, "Internal", http.StatusInternalServerError)
			srv.Logger.Error("Could not get user guid", "error", err.Error(), "token", accessToken)
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
