package postgres

import (
	"database/sql"

	_ "github.com/lib/pq"
	"github.com/teryble09/auth_service/app/model"
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
        refresh_token_hash TEXT NOT NULL,
        created_at         TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )`)
	if err != nil {
		return DB{}, err
	}

	stmtCreateNewSession, err = db.Prepare(`
		INSERT INTO sessions (user_guid, user_agent, ip, refresh_token_hash)
         VALUES ($1, $2, $3, $4)
         RETURNING session_id`)

	return DB{db}, err
}

var stmtCreateNewSession = &sql.Stmt{}

func (db DB) CreateNewSession(session model.Session) (sessionID int64, err error) {
	row := stmtCreateNewSession.QueryRow(session.UserGUID, session.UserAgent, session.IP, session.RefreshTokenHash)
	err = row.Scan(&sessionID)
	return
}
