package postgres

import (
	"database/sql"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/teryble09/auth_service/app/model"
	"github.com/teryble09/auth_service/app/storage"
)

type DB struct {
	cnn *sql.DB
}

func NewDatabaseConnection(cnnstring string) (DB, error) {
	db, err := sql.Open("postgres", cnnstring)
	if err != nil {
		return DB{}, err
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
    	session_id         BIGSERIAL PRIMARY KEY,
     	user_guid          UUID NOT NULL,
      	user_agent         TEXT NOT NULL,
        ip                 VARCHAR(45) NOT NULL,
        refresh_token_hash TEXT NOT NULL
        )`)
	if err != nil {
		return DB{}, err
	}

	stmtCreateNewSession, err = db.Prepare(`
		INSERT INTO sessions (user_guid, user_agent, ip, refresh_token_hash)
        VALUES ($1, $2, $3, $4)
        RETURNING session_id`)
	if err != nil {
		return DB{}, err
	}

	stmtSelectUserGuid, err = db.Prepare(`
		SELECT user_guid FROM sessions
		WHERE session_id = $1`)
	if err != nil {
		return DB{}, err
	}

	stmtSelectSession, err = db.Prepare(`
		SELECT * FROM sessions
		WHERE session_id = $1`)
	if err != nil {
		return DB{}, err
	}

	stmtRefreshSession, err = db.Prepare(`
		UPDATE sessions
		SET ip = $1, refresh_token_hash = $2
		WHERE session_id = $3
		`)
	if err != nil {
		return DB{}, err
	}

	stmtDeleteSession, err = db.Prepare(`
		DELETE FROM sessions
		WHERE session_id = $1`)
	return DB{db}, err

}

var stmtCreateNewSession = &sql.Stmt{}

func (db DB) CreateNewSession(session model.Session) (sessionID int64, err error) {
	row := stmtCreateNewSession.QueryRow(session.UserGUID, session.UserAgent, session.IP, session.RefreshTokenHash)
	err = row.Scan(&sessionID)
	return
}

var stmtSelectUserGuid = &sql.Stmt{}

func (db DB) GetUserGuid(sessionID int64) (uuid.UUID, error) {
	guid := uuid.UUID{}
	row := stmtSelectUserGuid.QueryRow(sessionID)
	err := row.Scan(&guid)
	if err == sql.ErrNoRows {
		return guid, storage.ErrSessionNotExist
	}
	return guid, err
}

var stmtSelectSession = &sql.Stmt{}

func (db DB) GetSession(sessionID int64) (model.Session, error) {
	session := model.Session{}
	row := stmtSelectUserGuid.QueryRow(sessionID)
	err := row.Scan(&session.SessionID, &session.UserGUID, &session.UserAgent, &session.IP, &session.RefreshTokenHash)
	if err == sql.ErrNoRows {
		return session, storage.ErrSessionNotExist
	}
	return session, err
}

var stmtRefreshSession = &sql.Stmt{}

func (db DB) RefreshSession(sessionID int64, newIP string, newHashedRefreshToken string) error {
	_, err := stmtRefreshSession.Exec(newIP, newHashedRefreshToken, sessionID)
	if err != nil {
		return err
	}
	return nil
}

var stmtDeleteSession = &sql.Stmt{}

func (db DB) DeleteSession(sessionID int64) error {
	_, err := stmtDeleteSession.Exec(sessionID)
	if err != nil {
		return err
	}
	return nil
}
