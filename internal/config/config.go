package config

import (
	"os"
	"strconv"
)

type Config struct {
	DatabaseURL          string
	JWTSecret            string
	JWTExpiryHours       int
	Port                 string
	GitHubClientID       string
	GitHubClientSecret   string
	GitHubRedirectURI    string
	OAuthSuccessRedirect string
}

func Load() Config {
	return Config{
		DatabaseURL:        env("DATABASE_URL_GENERAL", "postgres://osship:osship_secret@postgres:5432/osship?sslmode=disable&search_path=general"),
		JWTSecret:          env("JWT_SECRET", "dev-secret"),
		JWTExpiryHours:     envInt("JWT_EXPIRY_HOURS", 24),
		Port:               env("PORT", "8081"),
		GitHubClientID:     env("GITHUB_CLIENT_ID", ""),
		GitHubClientSecret: env("GITHUB_CLIENT_SECRET", ""),
		GitHubRedirectURI:    env("GITHUB_OAUTH_REDIRECT_URI", "http://localhost/api/v1/auth/oauth/github/callback"),
		OAuthSuccessRedirect: env("OAUTH_SUCCESS_REDIRECT", env("APP_BASE_URL", "http://localhost")+"/auth/github/callback"),
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
