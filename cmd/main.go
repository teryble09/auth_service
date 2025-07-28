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

	port = ":8080"

	if port == "" {
		panic("No port specified for server")
	}

	db, err := postgres.NewDatabaseConnection(fmt.Sprintf("port=5432 dbname=chat_db user=chat password=chat sslmode=disable"))
	if err != nil {
		panic(err.Error())
	}

	srv := service.AuthService{
		Logger: logger,
		DB:     db,
	}

	router := chi.NewRouter()

	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	router.Get("token", handler.NewSession(srv))

	http.ListenAndServe("1.1.1.1:"+port, router)
}
