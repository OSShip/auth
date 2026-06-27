package model

type User struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	Role           string `json:"role"`
	GithubUsername string `json:"github_username,omitempty"`
	DisplayName    string `json:"display_name,omitempty"`
}

type RegisterReq struct {
	Email          string `json:"email"`
	Password       string `json:"password"`
	Role           string `json:"role"`
	GithubUsername string `json:"github_username"`
	DisplayName    string `json:"display_name"`
}

type LoginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type TokenResp struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	User         User   `json:"user"`
}
