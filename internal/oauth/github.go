package oauth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/OSShip/auth/internal/handler"
	"github.com/OSShip/auth/internal/model"
	"github.com/OSShip/auth/internal/store"
	"github.com/google/uuid"
	"github.com/OSShip/utils/jwtutil"
	"github.com/OSShip/utils/observability"
)

type GitHub struct {
	Users              *store.Users
	JWTSecret          string
	ExpiryHours        int
	GitHubClientID     string
	GitHubClientSecret string
	GitHubRedirectURI  string
}

func (g *GitHub) Start(w http.ResponseWriter, r *http.Request) {
	if g.GitHubClientID == "" {
		slog.InfoContext(r.Context(), "GitHub OAuth stub response")
		handler.WriteJSON(w, http.StatusOK, map[string]interface{}{
			"stub":     true,
			"message":  "GitHub OAuth is not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET, or register with github_username.",
			"demo_url": fmt.Sprintf("%s?github_username=demo&email=demo@osship.local", g.GitHubRedirectURI),
		})
		return
	}
	state := uuid.New().String()
	slog.InfoContext(r.Context(), "GitHub OAuth redirect", "state", state)
	params := url.Values{
		"client_id":    {g.GitHubClientID},
		"redirect_uri": {g.GitHubRedirectURI},
		"scope":        {"read:user user:email"},
		"state":        {state},
	}
	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+params.Encode(), http.StatusFound)
}

func (g *GitHub) Callback(w http.ResponseWriter, r *http.Request) {
	if g.GitHubClientID == "" || g.GitHubClientSecret == "" {
		githubUsername := r.URL.Query().Get("github_username")
		email := r.URL.Query().Get("email")
		if githubUsername == "" || email == "" {
			slog.WarnContext(r.Context(), "OAuth stub missing params")
			http.Error(w, `{"error":"stub mode requires github_username and email query params"}`, http.StatusBadRequest)
			return
		}
		user, err := g.Users.FindOrCreateOAuthUser(r.Context(), email, githubUsername, "student")
		if err != nil {
			observability.RespondError(w, r, http.StatusInternalServerError, "internal", "oauth stub find or create user", err, "github", githubUsername)
			return
		}
		token, err := jwtutil.GenerateToken(g.JWTSecret, user.ID, user.Role, user.GithubUsername, g.ExpiryHours)
		if err != nil {
			observability.RespondError(w, r, http.StatusInternalServerError, "internal", "oauth stub generate token", err, "user_id", user.ID)
			return
		}
		slog.InfoContext(r.Context(), "OAuth stub login", "user_id", user.ID, "github", githubUsername)
		handler.WriteJSON(w, http.StatusOK, model.TokenResp{Token: token, User: user})
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, `{"error":"missing code"}`, http.StatusBadRequest)
		return
	}

	tokenReq, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(url.Values{
		"client_id":     {g.GitHubClientID},
		"client_secret": {g.GitHubClientSecret},
		"code":          {code},
		"redirect_uri":  {g.GitHubRedirectURI},
	}.Encode()))
	tokenReq.Header.Set("Accept", "application/json")
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	oauthHTTPResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		slog.ErrorContext(r.Context(), "GitHub token exchange failed", "err", err)
		http.Error(w, `{"error":"oauth token exchange failed"}`, http.StatusBadGateway)
		return
	}
	if oauthHTTPResp.StatusCode != http.StatusOK {
		slog.ErrorContext(r.Context(), "GitHub token exchange bad status", "status", oauthHTTPResp.StatusCode)
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

	user, err := g.Users.FindOrCreateOAuthUser(r.Context(), ghUser.Email, ghUser.Login, "student")
	if err != nil {
		observability.RespondError(w, r, http.StatusInternalServerError, "internal", "oauth find or create user", err, "github", ghUser.Login)
		return
	}
	token, err := jwtutil.GenerateToken(g.JWTSecret, user.ID, user.Role, user.GithubUsername, g.ExpiryHours)
	if err != nil {
		observability.RespondError(w, r, http.StatusInternalServerError, "internal", "oauth generate token", err, "user_id", user.ID)
		return
	}
	slog.InfoContext(r.Context(), "GitHub OAuth login", "user_id", user.ID, "github", ghUser.Login)
	handler.WriteJSON(w, http.StatusOK, model.TokenResp{Token: token, User: user})
}
