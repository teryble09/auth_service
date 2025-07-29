package service

import (
	"github.com/google/uuid"
	"github.com/teryble09/auth_service/app/model"
)

type Repository interface {
	CreateNewSession(model.Session) (sessionID int64, err error)
	RefreshSession(sessionID int64, newIP string, newHashedRefreshToken string) error
	GetUserGuid(sessionID int64) (uuid.UUID, error)
	GetSession(sessionID int64) (model.Session, error)
	DeleteSession(sessionID int64) error
}
