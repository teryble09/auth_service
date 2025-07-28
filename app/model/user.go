package model

import (
	"github.com/google/uuid"
)

type Session struct {
	SessionID        int64
	UserGUID         uuid.UUID
	UserAgent        string
	IP               string
	RefreshTokenHash string
}
