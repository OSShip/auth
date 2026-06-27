package handler

import (
	"encoding/json"
	"net/http"

	"github.com/OSShip/auth/internal/model"
	"github.com/OSShip/auth/internal/store"
	"github.com/google/uuid"
	"github.com/OSShip/utils/jwtutil"
	"github.com/OSShip/utils/passhash"
)

type Server struct {
	Users       *store.Users
	JWTSecret   string
	ExpiryHours int
}

func (s *Server) Register(w http.ResponseWriter, r *http.Request) {
	var req model.RegisterReq
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
	err = s.Users.CreateUser(r.Context(), id, req.Email, hash, salt, role, req.GithubUsername, req.DisplayName)
	if err != nil {
		http.Error(w, `{"error":"email already exists"}`, http.StatusConflict)
		return
	}

	token, err := jwtutil.GenerateToken(s.JWTSecret, id, role, req.GithubUsername, s.ExpiryHours)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	WriteJSON(w, http.StatusCreated, model.TokenResp{
		Token: token,
		User:  model.User{ID: id, Email: req.Email, Role: role, GithubUsername: req.GithubUsername, DisplayName: req.DisplayName},
	})
}

func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}

	id, email, role, hash, salt, github, display, err := s.Users.GetUserByEmailForLogin(r.Context(), req.Email)
	if err != nil {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}
	if !passhash.VerifyPassword(req.Password, salt, hash) {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	token, err := jwtutil.GenerateToken(s.JWTSecret, id, role, github, s.ExpiryHours)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	WriteJSON(w, http.StatusOK, model.TokenResp{
		Token: token,
		User:  model.User{ID: id, Email: email, Role: role, GithubUsername: github, DisplayName: display},
	})
}

func (s *Server) Refresh(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	tokenStr := auth
	if len(auth) > 7 && auth[:7] == "Bearer " {
		tokenStr = auth[7:]
	}
	claims, err := jwtutil.ValidateToken(s.JWTSecret, tokenStr)
	if err != nil {
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		return
	}
	token, err := jwtutil.GenerateToken(s.JWTSecret, claims.UserID, claims.Role, claims.GithubUsername, s.ExpiryHours)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (s *Server) Me(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-Id")
	if userID == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	u, err := s.Users.GetUserByID(r.Context(), userID)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	WriteJSON(w, http.StatusOK, u)
}

func WriteJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
