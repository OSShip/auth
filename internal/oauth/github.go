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
	Users                *store.Users
	JWTSecret            string
	ExpiryHours          int
	GitHubClientID       string
	GitHubClientSecret   string
	GitHubRedirectURI    string
	OAuthSuccessRedirect string
}

func wantsBrowserRedirect(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/html")
}

func (g *GitHub) respondToken(w http.ResponseWriter, r *http.Request, token string, user model.User) {
	if wantsBrowserRedirect(r) && g.OAuthSuccessRedirect != "" {
		u, err := url.Parse(g.OAuthSuccessRedirect)
		if err == nil {
			q := u.Query()
			q.Set("token", token)
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}
	handler.WriteJSON(w, http.StatusOK, model.TokenResp{Token: token, User: user})
}

func (g *GitHub) respondOAuthError(w http.ResponseWriter, r *http.Request, status int, code string) {
	if wantsBrowserRedirect(r) && g.OAuthSuccessRedirect != "" {
		u, err := url.Parse(g.OAuthSuccessRedirect)
		if err == nil {
			q := u.Query()
			q.Set("error", code)
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}
	http.Error(w, fmt.Sprintf(`{"error":"%s"}`, code), status)
}

func (g *GitHub) Start(w http.ResponseWriter, r *http.Request) {
	if g.GitHubClientID == "" {
		if wantsBrowserRedirect(r) {
			cb, err := url.Parse(g.GitHubRedirectURI)
			if err == nil {
				q := cb.Query()
				q.Set("github_username", "demo")
				q.Set("email", "demo@osship.local")
				cb.RawQuery = q.Encode()
				http.Redirect(w, r, cb.String(), http.StatusFound)
				return
			}
		}
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
			g.respondOAuthError(w, r, http.StatusBadRequest, "stub_missing_params")
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
		g.respondToken(w, r, token, user)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		g.respondOAuthError(w, r, http.StatusBadRequest, "missing_code")
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
		g.respondOAuthError(w, r, http.StatusBadGateway, "token_exchange_failed")
		return
	}
	if oauthHTTPResp.StatusCode != http.StatusOK {
		slog.ErrorContext(r.Context(), "GitHub token exchange bad status", "status", oauthHTTPResp.StatusCode)
		g.respondOAuthError(w, r, http.StatusBadGateway, "token_exchange_failed")
		return
	}
	defer oauthHTTPResp.Body.Close()

	var oauthToken struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(oauthHTTPResp.Body).Decode(&oauthToken); err != nil || oauthToken.AccessToken == "" {
		g.respondOAuthError(w, r, http.StatusBadGateway, "invalid_oauth_response")
		return
	}

	ghReq, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://api.github.com/user", nil)
	ghReq.Header.Set("Authorization", "Bearer "+oauthToken.AccessToken)
	ghReq.Header.Set("Accept", "application/vnd.github+json")
	ghResp, err := http.DefaultClient.Do(ghReq)
	if err != nil || ghResp.StatusCode != http.StatusOK {
		g.respondOAuthError(w, r, http.StatusBadGateway, "github_user_fetch_failed")
		return
	}
	defer ghResp.Body.Close()

	var ghUser struct {
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(ghResp.Body).Decode(&ghUser); err != nil || ghUser.Login == "" {
		g.respondOAuthError(w, r, http.StatusBadGateway, "invalid_github_user")
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
	g.respondToken(w, r, token, user)
}
