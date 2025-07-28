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
	db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
    	session_id         BIGSERIAL PRIMARY KEY,
     	user_guid          UUID NOT NULL,
      	user_agent         TEXT NOT NULL,
        ip                 VARCHAR(45) NOT NULL,
        refresh_token_hash TEXT NOT NULL,
        created_at         TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )`)

	return DB{db}, err
}

func (db DB) CreateNewSession(session model.Session) (sessionID int64, err error) {

}
