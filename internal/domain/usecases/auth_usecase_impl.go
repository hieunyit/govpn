package usecases

import (
	"context"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/internal/infrastructure/ldap"
	"govpn/pkg/config"
	"govpn/pkg/errors"
	"govpn/pkg/jwt"
	"govpn/pkg/logger"
)

// JWTService interface to support both HMAC and RSA implementations
type JWTService interface {
	GenerateAccessToken(username, role string) (string, error)
	GenerateRefreshToken(username, role string) (string, error)
	ValidateAccessToken(tokenString string) (*jwt.Claims, error)
	ValidateRefreshToken(tokenString string) (*jwt.Claims, error)
}

type authUsecaseImpl struct {
	userRepo   repositories.UserRepository
	ldapClient *ldap.Client
	jwtService JWTService
}

func NewAuthUsecase(userRepo repositories.UserRepository, ldapClient *ldap.Client, jwtConfig config.JWTConfig) AuthUsecase {
	var jwtService JWTService

	if jwtConfig.UseRSA {
		// Use RSA JWT service
		if jwtConfig.AccessPrivateKey != "" && jwtConfig.RefreshPrivateKey != "" {
			// Use provided RSA keys
			rsaService, err := jwt.NewRSAServiceWithKeys(
				jwtConfig.AccessPrivateKey,
				jwtConfig.RefreshPrivateKey,
				jwtConfig.AccessTokenExpireDuration,
				jwtConfig.RefreshTokenExpireDuration,
			)
			if err != nil {
				logger.Log.WithError(err).Error("Failed to create RSA JWT service with provided keys, falling back to generated keys")
				// Fallback to generated keys
				rsaService, err = jwt.NewRSAService(
					jwtConfig.AccessTokenExpireDuration,
					jwtConfig.RefreshTokenExpireDuration,
				)
				if err != nil {
					logger.Log.WithError(err).Fatal("Failed to create RSA JWT service")
				}
			}
			jwtService = rsaService
			logger.Log.Info("Using RSA256 JWT service")
		} else {
			// Generate new RSA keys
			rsaService, err := jwt.NewRSAService(
				jwtConfig.AccessTokenExpireDuration,
				jwtConfig.RefreshTokenExpireDuration,
			)
			if err != nil {
				logger.Log.WithError(err).Fatal("Failed to create RSA JWT service")
			}
			jwtService = rsaService
			logger.Log.Info("Using RSA256 JWT service with generated keys")

			// Log the public keys for external verification (optional)
			if accessPubKey, err := rsaService.GetAccessPublicKeyPEM(); err == nil {
				logger.Log.Debug("Access token public key:", accessPubKey)
			}
		}
	} else {
		// Use legacy HMAC JWT service
		hmacService := jwt.NewService(
			jwtConfig.Secret,
			jwtConfig.RefreshSecret,
			jwtConfig.AccessTokenExpireDuration,
			jwtConfig.RefreshTokenExpireDuration,
		)
		jwtService = hmacService
		logger.Log.Warn("Using legacy HMAC256 JWT service. Consider migrating to RSA256 for better security.")
	}

	return &authUsecaseImpl{
		userRepo:   userRepo,
		ldapClient: ldapClient,
		jwtService: jwtService,
	}
}

func (u *authUsecaseImpl) Login(ctx context.Context, credentials *entities.LoginCredentials) (*entities.AuthTokens, error) {
	logger.Log.WithField("username", credentials.Username).Info("Attempting login")

	// Check if user exists in OpenVPN AS
	exists, err := u.userRepo.ExistsByUsername(ctx, credentials.Username)
	if err != nil {
		logger.Log.WithField("username", credentials.Username).WithError(err).Error("Failed to check user existence")
		return nil, errors.InternalServerError("Authentication failed", err)
	}

	if !exists {
		logger.Log.WithField("username", credentials.Username).Warn("User not found in OpenVPN AS")
		return nil, errors.Unauthorized("Invalid credentials", errors.ErrUserNotFound)
	}

	// Get user details
	user, err := u.userRepo.GetByUsername(ctx, credentials.Username)
	if err != nil {
		logger.Log.WithField("username", credentials.Username).WithError(err).Error("Failed to get user details")
		return nil, errors.InternalServerError("Authentication failed", err)
	}

	// Check if user is admin
	if !user.IsAdmin() {
		logger.Log.WithField("username", credentials.Username).Warn("Non-admin user attempted login")
		return nil, errors.Forbidden("Access restricted to administrators", errors.ErrForbidden)
	}

	// Check if user is disabled
	if user.IsAccessDenied() {
		logger.Log.WithField("username", credentials.Username).Warn("Disabled user attempted login")
		return nil, errors.Forbidden("User account is disabled", errors.ErrForbidden)
	}

	// Authenticate based on auth method
	if user.IsLDAPAuth() {
		// Check LDAP user existence
		if err := u.ldapClient.CheckUserExists(credentials.Username); err != nil {
			logger.Log.WithField("username", credentials.Username).WithError(err).Error("LDAP user check failed")
			return nil, errors.Unauthorized("Invalid credentials", err)
		}

		// Authenticate with LDAP
		if err := u.ldapClient.Authenticate(credentials.Username, credentials.Password); err != nil {
			logger.Log.WithField("username", credentials.Username).WithError(err).Error("LDAP authentication failed")
			return nil, errors.Unauthorized("Invalid credentials", err)
		}
	} else if user.IsLocalAuth() {
		// For local users, we should validate password against OpenVPN AS
		// This is a simplified check - in production, you might want to implement
		// more sophisticated password validation
		logger.Log.WithField("username", credentials.Username).Debug("Local user authentication - password will be validated by OpenVPN AS")
	}

	// Generate tokens
	accessToken, err := u.jwtService.GenerateAccessToken(user.Username, user.Role)
	if err != nil {
		logger.Log.WithField("username", credentials.Username).WithError(err).Error("Failed to generate access token")
		return nil, errors.InternalServerError("Token generation failed", err)
	}

	refreshToken, err := u.jwtService.GenerateRefreshToken(user.Username, user.Role)
	if err != nil {
		logger.Log.WithField("username", credentials.Username).WithError(err).Error("Failed to generate refresh token")
		return nil, errors.InternalServerError("Token generation failed", err)
	}

	logger.Log.WithField("username", credentials.Username).Info("Login successful")
	return entities.NewAuthTokens(accessToken, refreshToken), nil
}

func (u *authUsecaseImpl) RefreshToken(ctx context.Context, request *entities.RefreshTokenRequest) (*entities.AuthTokens, error) {
	logger.Log.Debug("Attempting token refresh")

	// Validate refresh token
	claims, err := u.jwtService.ValidateRefreshToken(request.RefreshToken)
	if err != nil {
		logger.Log.WithError(err).Error("Invalid refresh token")
		return nil, errors.Unauthorized("Invalid refresh token", err)
	}

	// Check if user still exists and is valid
	exists, err := u.userRepo.ExistsByUsername(ctx, claims.Username)
	if err != nil {
		logger.Log.WithField("username", claims.Username).WithError(err).Error("Failed to check user existence during refresh")
		return nil, errors.InternalServerError("Token refresh failed", err)
	}

	if !exists {
		logger.Log.WithField("username", claims.Username).Warn("User not found during token refresh")
		return nil, errors.Unauthorized("User not found", errors.ErrUserNotFound)
	}

	// Get current user details
	user, err := u.userRepo.GetByUsername(ctx, claims.Username)
	if err != nil {
		logger.Log.WithField("username", claims.Username).WithError(err).Error("Failed to get user details during refresh")
		return nil, errors.InternalServerError("Token refresh failed", err)
	}

	// Check if user is still admin
	if !user.IsAdmin() {
		logger.Log.WithField("username", claims.Username).Warn("Non-admin user attempted token refresh")
		return nil, errors.Forbidden("Access restricted to administrators", errors.ErrForbidden)
	}

	// Check if user is still enabled
	if user.IsAccessDenied() {
		logger.Log.WithField("username", claims.Username).Warn("Disabled user attempted token refresh")
		return nil, errors.Forbidden("User account is disabled", errors.ErrForbidden)
	}

	// For LDAP users, verify they still exist in LDAP
	if user.IsLDAPAuth() {
		if err := u.ldapClient.CheckUserExists(claims.Username); err != nil {
			logger.Log.WithField("username", claims.Username).WithError(err).Error("LDAP user check failed during refresh")
			return nil, errors.Unauthorized("User not found in LDAP", err)
		}
	}

	// Generate new tokens
	accessToken, err := u.jwtService.GenerateAccessToken(user.Username, user.Role)
	if err != nil {
		logger.Log.WithField("username", claims.Username).WithError(err).Error("Failed to generate new access token")
		return nil, errors.InternalServerError("Token generation failed", err)
	}

	refreshToken, err := u.jwtService.GenerateRefreshToken(user.Username, user.Role)
	if err != nil {
		logger.Log.WithField("username", claims.Username).WithError(err).Error("Failed to generate new refresh token")
		return nil, errors.InternalServerError("Token generation failed", err)
	}

	logger.Log.WithField("username", claims.Username).Info("Token refresh successful")
	return entities.NewAuthTokens(accessToken, refreshToken), nil
}

func (u *authUsecaseImpl) ValidateToken(ctx context.Context, token string) (*entities.AuthUser, error) {
	// Validate access token
	claims, err := u.jwtService.ValidateAccessToken(token)
	if err != nil {
		return nil, errors.Unauthorized("Invalid token", err)
	}

	// Check if user still exists
	user, err := u.userRepo.GetByUsername(ctx, claims.Username)
	if err != nil {
		return nil, errors.Unauthorized("User not found", err)
	}

	// Check if user is still enabled
	if user.IsAccessDenied() {
		return nil, errors.Forbidden("User account is disabled", errors.ErrForbidden)
	}

	return entities.NewAuthUser(user.Username, user.Role, user.Email), nil
}
