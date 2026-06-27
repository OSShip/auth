package store

import (
	"context"

	"github.com/OSShip/auth/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/OSShip/utils/passhash"
)

type Users struct {
	Pool *pgxpool.Pool
}

func (s *Users) CreateUser(ctx context.Context, id, email, hash, salt, role, githubUsername, displayName string) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO users (id, email, password_hash, password_salt, role, github_username, display_name) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, email, hash, salt, role, nullStr(githubUsername), nullStr(displayName))
	return err
}

func (s *Users) GetUserByEmailForLogin(ctx context.Context, email string) (id, userEmail, role, hash, salt, github, display string, err error) {
	err = s.Pool.QueryRow(ctx,
		`SELECT id, email, role, password_hash, COALESCE(password_salt,''), COALESCE(github_username,''), COALESCE(display_name,'') FROM users WHERE email=$1`,
		email).Scan(&id, &userEmail, &role, &hash, &salt, &github, &display)
	return
}

func (s *Users) GetUserByID(ctx context.Context, userID string) (model.User, error) {
	var u model.User
	err := s.Pool.QueryRow(ctx,
		`SELECT id, email, role, COALESCE(github_username,''), COALESCE(display_name,'') FROM users WHERE id=$1`, userID).
		Scan(&u.ID, &u.Email, &u.Role, &u.GithubUsername, &u.DisplayName)
	return u, err
}

func (s *Users) FindOrCreateOAuthUser(ctx context.Context, email, githubUsername, role string) (model.User, error) {
	var u model.User
	err := s.Pool.QueryRow(ctx,
		`SELECT id, email, role, COALESCE(github_username,''), COALESCE(display_name,'') FROM users WHERE email=$1 OR github_username=$2`,
		email, githubUsername).Scan(&u.ID, &u.Email, &u.Role, &u.GithubUsername, &u.DisplayName)
	if err == nil {
		if u.GithubUsername == "" {
			_, _ = s.Pool.Exec(ctx, `UPDATE users SET github_username=$1, updated_at=NOW() WHERE id=$2`, githubUsername, u.ID)
			u.GithubUsername = githubUsername
		}
		return u, nil
	}

	id := uuid.New().String()
	oauthPass := uuid.New().String()
	salt, hash, err := passhash.HashPasswordPair(oauthPass)
	if err != nil {
		return model.User{}, err
	}
	_, err = s.Pool.Exec(ctx,
		`INSERT INTO users (id, email, password_hash, password_salt, role, github_username, display_name) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, email, hash, salt, role, githubUsername, githubUsername)
	if err != nil {
		return model.User{}, err
	}
	return model.User{ID: id, Email: email, Role: role, GithubUsername: githubUsername, DisplayName: githubUsername}, nil
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
