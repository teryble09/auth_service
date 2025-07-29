package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/teryble09/auth_service/app/handler"
	"github.com/teryble09/auth_service/app/service"
	"github.com/teryble09/auth_service/app/storage/postgres"
)

func main() {
	logger := slog.Default()

	port := os.Getenv("PORT")

	port = "8080"

	if port == "" {
		panic("No port specified for server")
	}

	db, err := postgres.NewDatabaseConnection(fmt.Sprintf("port=5432 dbname=chat_db user=chat password=chat sslmode=disable"))
	if err != nil {
		panic(err.Error())
	}

	srv := &service.AuthService{
		Logger: logger,
		DB:     db,
	}

	router := chi.NewRouter()

	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	router.Post("/token", handler.NewSession(srv))

	err = http.ListenAndServe("0.0.0.0:"+port, router)
	if err != nil {
		panic(err)
	}
}
