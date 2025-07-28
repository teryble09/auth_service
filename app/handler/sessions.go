package handler

import (
	"encoding/json"
	"net/http"

	"github.com/teryble09/auth_service/app/dto"
	"github.com/teryble09/auth_service/app/service"
)

func NewSession(srv *service.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := dto.NewSessionRequest{}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		req.IP = r.RemoteAddr
		req.UserAgent = r.UserAgent()

		resp, err := srv.NewSession(req)
	}
}
