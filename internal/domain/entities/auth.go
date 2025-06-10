package entities

type AuthTokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type AuthUser struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Email    string `json:"email"`
}

type LoginCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// Methods
func NewAuthTokens(accessToken, refreshToken string) *AuthTokens {
	return &AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
}

func NewAuthUser(username, role, email string) *AuthUser {
	return &AuthUser{
		Username: username,
		Role:     role,
		Email:    email,
	}
}

func (a *AuthUser) IsAdmin() bool {
	return a.Role == UserRoleAdmin
}
