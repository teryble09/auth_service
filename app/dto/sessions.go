package dto

import (
	"github.com/google/uuid"
)

type NewSessionRequest struct {
	UserGUID  uuid.UUID `json:"user_guid"`
	UserAgent string
	IP        string
}

type NewSessionResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
