package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type RSAService struct {
	privateKey        *rsa.PrivateKey
	publicKey         *rsa.PublicKey
	refreshPrivateKey *rsa.PrivateKey
	refreshPublicKey  *rsa.PublicKey
	accessExpiry      time.Duration
	refreshExpiry     time.Duration
}

// NewRSAService creates a new JWT service with RSA256 signing
func NewRSAService(accessExpiry, refreshExpiry time.Duration) (*RSAService, error) {
	// Generate RSA key pairs
	accessPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access RSA key: %w", err)
	}

	refreshPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh RSA key: %w", err)
	}

	return &RSAService{
		privateKey:        accessPrivateKey,
		publicKey:         &accessPrivateKey.PublicKey,
		refreshPrivateKey: refreshPrivateKey,
		refreshPublicKey:  &refreshPrivateKey.PublicKey,
		accessExpiry:      accessExpiry,
		refreshExpiry:     refreshExpiry,
	}, nil
}

// NewRSAServiceWithKeys creates a new JWT service with provided RSA keys
func NewRSAServiceWithKeys(privateKeyPEM, refreshPrivateKeyPEM string, accessExpiry, refreshExpiry time.Duration) (*RSAService, error) {
	// Parse access token private key
	accessPrivateKey, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse access private key: %w", err)
	}

	// Parse refresh token private key
	refreshPrivateKey, err := parseRSAPrivateKey(refreshPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh private key: %w", err)
	}

	return &RSAService{
		privateKey:        accessPrivateKey,
		publicKey:         &accessPrivateKey.PublicKey,
		refreshPrivateKey: refreshPrivateKey,
		refreshPublicKey:  &refreshPrivateKey.PublicKey,
		accessExpiry:      accessExpiry,
		refreshExpiry:     refreshExpiry,
	}, nil
}

func parseRSAPrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}

		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not RSA private key")
		}
		return rsaKey, nil
	}

	return privateKey, nil
}

func (s *RSAService) GenerateAccessToken(username, role string) (string, error) {
	claims := &Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.accessExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "govpn-api",
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.privateKey)
}

func (s *RSAService) GenerateRefreshToken(username, role string) (string, error) {
	claims := &Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.refreshExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "govpn-api",
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.refreshPrivateKey)
}

func (s *RSAService) ValidateAccessToken(tokenString string) (*Claims, error) {
	return s.validateToken(tokenString, s.publicKey)
}

func (s *RSAService) ValidateRefreshToken(tokenString string) (*Claims, error) {
	return s.validateToken(tokenString, s.refreshPublicKey)
}

func (s *RSAService) validateToken(tokenString string, publicKey *rsa.PublicKey) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrInvalidKey
}

// GetPublicKeyPEM returns the public key in PEM format for external verification
func (s *RSAService) GetAccessPublicKeyPEM() (string, error) {
	return s.publicKeyToPEM(s.publicKey)
}

func (s *RSAService) GetRefreshPublicKeyPEM() (string, error) {
	return s.publicKeyToPEM(s.refreshPublicKey)
}

func (s *RSAService) publicKeyToPEM(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), nil
}

// GetPrivateKeyPEM returns the private key in PEM format (use carefully!)
func (s *RSAService) GetAccessPrivateKeyPEM() (string, error) {
	return s.privateKeyToPEM(s.privateKey)
}

func (s *RSAService) GetRefreshPrivateKeyPEM() (string, error) {
	return s.privateKeyToPEM(s.refreshPrivateKey)
}

func (s *RSAService) privateKeyToPEM(privateKey *rsa.PrivateKey) (string, error) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return string(privateKeyPEM), nil
}

// GenerateKeyPair generates a new RSA key pair and returns PEM encoded strings
func GenerateRSAKeyPair() (privateKeyPEM, publicKeyPEM string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Private key to PEM
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}))

	// Public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}))

	return privateKeyPEM, publicKeyPEM, nil
}
