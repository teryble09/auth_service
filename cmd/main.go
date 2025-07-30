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

	port := "8080"

	cnnstring := fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
	)

	db, err := postgres.NewDatabaseConnection(cnnstring)
	if err != nil {
		panic(err.Error())
	}

	blacklist := cache.New(time.Hour, time.Minute*5)

	srv := &service.AuthService{
		Logger:        logger,
		DB:            db,
		TokenLivetime: time.Minute * 15,
		Secret:        os.Getenv("JWT_SECRET"),
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

	srv.Logger.Info("Starting server on port: " + port)
	err = http.ListenAndServe("0.0.0.0:"+port, router)
	if err != nil {
		panic(err)
	}
}
