package dto

type LoginRequest struct {
	Username string `json:"username" binding:"required" validate:"required,min=3,max=50"`
	Password string `json:"password" binding:"required" validate:"required,min=1"`
}

type LoginResponse struct {
	AccessToken  string   `json:"accessToken"`
	RefreshToken string   `json:"refreshToken"`
	User         UserInfo `json:"user"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken" binding:"required" validate:"required"`
}

type RefreshTokenResponse struct {
	AccessToken  string   `json:"accessToken"`
	RefreshToken string   `json:"refreshToken"`
	User         UserInfo `json:"user"`
}

type UserInfo struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

// Validation messages
func (r LoginRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Username.required": "Username is required",
		"Username.min":      "Username must be at least 3 characters",
		"Username.max":      "Username must not exceed 50 characters",
		"Password.required": "Password is required",
	}
}

func (r RefreshTokenRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"RefreshToken.required": "Refresh token is required",
	}
}
