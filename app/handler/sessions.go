package handler

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/teryble09/auth_service/app/dto"
	"github.com/teryble09/auth_service/app/service"
)

func NewSession(srv *service.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		req := dto.NewSessionRequest{}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		req.IP, _, _ = net.SplitHostPort(r.RemoteAddr)
		req.UserAgent = r.UserAgent()

		resp, err := srv.NewSession(req)
		if err != nil {
			http.Error(w, "Could not create new session", http.StatusInternalServerError)
		}

		w.Header().Add("Content-Type", "application-json")
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			srv.Logger.Error("Could not create json response", "error", err.Error())
		}
	}
}
