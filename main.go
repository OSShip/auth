package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/OSShip/auth/internal/config"
	"github.com/OSShip/auth/internal/handler"
	"github.com/OSShip/auth/internal/oauth"
	"github.com/OSShip/auth/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/OSShip/utils/observability"
)

func main() {
	cfg := config.Load()
	observability.InitSentry("auth")
	defer observability.FlushSentry(2 * time.Second)

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	users := &store.Users{Pool: pool}
	srv := &handler.Server{Users: users, JWTSecret: cfg.JWTSecret, ExpiryHours: cfg.JWTExpiryHours}
	gh := &oauth.GitHub{
		Users:              users,
		JWTSecret:          cfg.JWTSecret,
		ExpiryHours:        cfg.JWTExpiryHours,
		GitHubClientID:     cfg.GitHubClientID,
		GitHubClientSecret: cfg.GitHubClientSecret,
		GitHubRedirectURI:  cfg.GitHubRedirectURI,
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(observability.SentryRecoverMiddleware("auth"))
	r.Use(observability.SentryErrorMiddleware("auth"))
	r.Use(observability.PrometheusMiddleware("auth"))

	r.Get("/health", observability.HealthHandler("auth"))
	r.Get("/metrics", observability.MetricsHandler().ServeHTTP)

	r.Post("/register", srv.Register)
	r.Post("/login", srv.Login)
	r.Post("/refresh", srv.Refresh)
	r.Get("/me", srv.Me)
	r.Get("/oauth/github", gh.Start)
	r.Get("/oauth/github/callback", gh.Callback)

	log.Printf("auth listening on :%s", cfg.Port)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, r))
}
