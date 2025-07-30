package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/patrickmn/go-cache"
	"github.com/teryble09/auth_service/app/custom_middleware"
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

	blacklist := cache.New(time.Hour, time.Minute*5)

	srv := &service.AuthService{
		Logger:        logger,
		DB:            db,
		TokenLivetime: time.Second,
		Secret:        "asdf",
		BlackList:     blacklist,
	}

	router := chi.NewRouter()

	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	authMidlleware := custom_middleware.NewVerifyToken(srv.Secret, srv.BlackList)

	router.Post("/token", handler.NewSession(srv))
	router.With(authMidlleware).Get("/user_guid", handler.GetUserGuid(srv))
	router.With(authMidlleware).Post("/refresh", handler.RefreshToken(srv))
	router.With(authMidlleware).Delete("/deactivate", handler.DeactivateSession(srv))

	err = http.ListenAndServe("0.0.0.0:"+port, router)
	if err != nil {
		panic(err)
	}
}
