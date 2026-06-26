package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/OSShip/utils/jwtutil"
	"github.com/OSShip/utils/observability"
	"github.com/OSShip/utils/passhash"
)

type User struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	Role           string `json:"role"`
	GithubUsername string `json:"github_username,omitempty"`
	DisplayName    string `json:"display_name,omitempty"`
}

type registerReq struct {
	Email          string `json:"email"`
	Password       string `json:"password"`
	Role           string `json:"role"`
	GithubUsername string `json:"github_username"`
	DisplayName    string `json:"display_name"`
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type tokenResp struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	User         User   `json:"user"`
}

func main() {
	dbURL := env("DATABASE_URL_GENERAL", "postgres://osship:osship_secret@postgres:5432/osship?sslmode=disable&search_path=general")
	jwtSecret := env("JWT_SECRET", "dev-secret")
	expiryHours := envInt("JWT_EXPIRY_HOURS", 24)
	port := env("PORT", "8081")
	githubClientID := env("GITHUB_CLIENT_ID", "")
	githubClientSecret := env("GITHUB_CLIENT_SECRET", "")
	githubRedirectURI := env("GITHUB_OAUTH_REDIRECT_URI", "http://localhost/api/v1/auth/oauth/github/callback")

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	s := &server{
		pool:               pool,
		jwtSecret:          jwtSecret,
		expiryHours:        expiryHours,
		githubClientID:     githubClientID,
		githubClientSecret: githubClientSecret,
		githubRedirectURI:  githubRedirectURI,
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(observability.PrometheusMiddleware("auth"))

	r.Get("/health", observability.HealthHandler("auth"))
	r.Get("/metrics", observability.MetricsHandler().ServeHTTP)

	r.Post("/register", s.register)
	r.Post("/login", s.login)
	r.Post("/refresh", s.refresh)
	r.Get("/me", s.me)
	r.Get("/oauth/github", s.githubOAuthStart)
	r.Get("/oauth/github/callback", s.githubOAuthCallback)

	log.Printf("auth listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

type server struct {
	pool               *pgxpool.Pool
	jwtSecret          string
	expiryHours        int
	githubClientID     string
	githubClientSecret string
	githubRedirectURI  string
}

func (s *server) register(w http.ResponseWriter, r *http.Request) {
	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.Password == "" {
		http.Error(w, `{"error":"email and password required"}`, http.StatusBadRequest)
		return
	}
	role := req.Role
	if role == "" {
		role = "student"
	}
	if role != "student" && role != "mentor" && role != "admin" {
		http.Error(w, `{"error":"invalid role"}`, http.StatusBadRequest)
		return
	}

	salt, hash, err := passhash.HashPasswordPair(req.Password)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	id := uuid.New().String()
	_, err = s.pool.Exec(r.Context(),
		`INSERT INTO users (id, email, password_hash, password_salt, role, github_username, display_name) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, req.Email, hash, salt, role, nullStr(req.GithubUsername), nullStr(req.DisplayName))
	if err != nil {
		http.Error(w, `{"error":"email already exists"}`, http.StatusConflict)
		return
	}

	token, err := jwtutil.GenerateToken(s.jwtSecret, id, role, req.GithubUsername, s.expiryHours)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, tokenResp{
		Token: token,
		User: User{ID: id, Email: req.Email, Role: role, GithubUsername: req.GithubUsername, DisplayName: req.DisplayName},
	})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}

	var id, email, role, hash, salt, github, display string
	err := s.pool.QueryRow(r.Context(),
		`SELECT id, email, role, password_hash, COALESCE(password_salt,''), COALESCE(github_username,''), COALESCE(display_name,'') FROM users WHERE email=$1`,
		req.Email).Scan(&id, &email, &role, &hash, &salt, &github, &display)
	if err != nil {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}
	if !passhash.VerifyPassword(req.Password, salt, hash) {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	token, err := jwtutil.GenerateToken(s.jwtSecret, id, role, github, s.expiryHours)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, tokenResp{
		Token: token,
		User:  User{ID: id, Email: email, Role: role, GithubUsername: github, DisplayName: display},
	})
}

func (s *server) refresh(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	tokenStr := auth
	if len(auth) > 7 && auth[:7] == "Bearer " {
		tokenStr = auth[7:]
	}
	claims, err := jwtutil.ValidateToken(s.jwtSecret, tokenStr)
	if err != nil {
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		return
	}
	token, err := jwtutil.GenerateToken(s.jwtSecret, claims.UserID, claims.Role, claims.GithubUsername, s.expiryHours)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (s *server) me(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-Id")
	if userID == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var u User
	err := s.pool.QueryRow(r.Context(),
		`SELECT id, email, role, COALESCE(github_username,''), COALESCE(display_name,'') FROM users WHERE id=$1`, userID).
		Scan(&u.ID, &u.Email, &u.Role, &u.GithubUsername, &u.DisplayName)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *server) githubOAuthStart(w http.ResponseWriter, r *http.Request) {
	if s.githubClientID == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"stub":    true,
			"message": "GitHub OAuth is not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET, or register with github_username.",
			"demo_url": fmt.Sprintf("%s?github_username=demo&email=demo@osship.local", s.githubRedirectURI),
		})
		return
	}
	state := uuid.New().String()
	params := url.Values{
		"client_id":    {s.githubClientID},
		"redirect_uri": {s.githubRedirectURI},
		"scope":        {"read:user user:email"},
		"state":        {state},
	}
	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+params.Encode(), http.StatusFound)
}

func (s *server) githubOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if s.githubClientID == "" || s.githubClientSecret == "" {
		githubUsername := r.URL.Query().Get("github_username")
		email := r.URL.Query().Get("email")
		if githubUsername == "" || email == "" {
			http.Error(w, `{"error":"stub mode requires github_username and email query params"}`, http.StatusBadRequest)
			return
		}
		user, err := s.findOrCreateOAuthUser(r.Context(), email, githubUsername, "student")
		if err != nil {
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
		token, err := jwtutil.GenerateToken(s.jwtSecret, user.ID, user.Role, user.GithubUsername, s.expiryHours)
		if err != nil {
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, tokenResp{Token: token, User: user})
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, `{"error":"missing code"}`, http.StatusBadRequest)
		return
	}

	tokenReq, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(url.Values{
		"client_id":     {s.githubClientID},
		"client_secret": {s.githubClientSecret},
		"code":          {code},
		"redirect_uri":  {s.githubRedirectURI},
	}.Encode()))
	tokenReq.Header.Set("Accept", "application/json")
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	oauthHTTPResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil || oauthHTTPResp.StatusCode != http.StatusOK {
		http.Error(w, `{"error":"oauth token exchange failed"}`, http.StatusBadGateway)
		return
	}
	defer oauthHTTPResp.Body.Close()

	var oauthToken struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(oauthHTTPResp.Body).Decode(&oauthToken); err != nil || oauthToken.AccessToken == "" {
		http.Error(w, `{"error":"invalid oauth response"}`, http.StatusBadGateway)
		return
	}

	ghReq, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://api.github.com/user", nil)
	ghReq.Header.Set("Authorization", "Bearer "+oauthToken.AccessToken)
	ghReq.Header.Set("Accept", "application/vnd.github+json")
	ghResp, err := http.DefaultClient.Do(ghReq)
	if err != nil || ghResp.StatusCode != http.StatusOK {
		http.Error(w, `{"error":"github user fetch failed"}`, http.StatusBadGateway)
		return
	}
	defer ghResp.Body.Close()

	var ghUser struct {
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(ghResp.Body).Decode(&ghUser); err != nil || ghUser.Login == "" {
		http.Error(w, `{"error":"invalid github user"}`, http.StatusBadGateway)
		return
	}
	if ghUser.Email == "" {
		ghUser.Email = ghUser.Login + "@users.noreply.github.com"
	}

	user, err := s.findOrCreateOAuthUser(r.Context(), ghUser.Email, ghUser.Login, "student")
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	token, err := jwtutil.GenerateToken(s.jwtSecret, user.ID, user.Role, user.GithubUsername, s.expiryHours)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, tokenResp{Token: token, User: user})
}

func (s *server) findOrCreateOAuthUser(ctx context.Context, email, githubUsername, role string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, role, COALESCE(github_username,''), COALESCE(display_name,'') FROM users WHERE email=$1 OR github_username=$2`,
		email, githubUsername).Scan(&u.ID, &u.Email, &u.Role, &u.GithubUsername, &u.DisplayName)
	if err == nil {
		if u.GithubUsername == "" {
			_, _ = s.pool.Exec(ctx, `UPDATE users SET github_username=$1, updated_at=NOW() WHERE id=$2`, githubUsername, u.ID)
			u.GithubUsername = githubUsername
		}
		return u, nil
	}

	id := uuid.New().String()
	oauthPass := uuid.New().String()
	salt, hash, err := passhash.HashPasswordPair(oauthPass)
	if err != nil {
		return User{}, err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO users (id, email, password_hash, password_salt, role, github_username, display_name) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, email, hash, salt, role, githubUsername, githubUsername)
	if err != nil {
		return User{}, err
	}
	return User{ID: id, Email: email, Role: role, GithubUsername: githubUsername, DisplayName: githubUsername}, nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
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

var _ = io.Discard
