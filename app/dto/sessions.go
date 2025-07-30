package dto

import (
	"time"

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

type RefreshPairRequest struct {
	AccessToken  string
	RefreshToken string `json:"refresh_token"`

	SessionID int64
	UserAgent string
	IP        string
}

type RefreshPairResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type GetUserGuidRequest struct {
	SessionID int64
}

type GetUserGuidResponse struct {
	UserGUID uuid.UUID `json:"user_guid"`
}

type DeactivateSessionRequest struct {
	AccessToken string
	SessionID   int64
}

type WebhookPostMessage struct {
	UserGUID uuid.UUID `json:"user_guid"`
	OldIP    string    `json:"old_ip"`
	NewIP    string    `json:"new_ip"`
	Time     time.Time `json:"time"`
}
