package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// MakeJWT creates a new JWT token for a given user
func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	// Create the claims
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   userID.String(),
	}

	// Create a new token with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret
	tokenString, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateJWT validates a JWT token and returns the user ID
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	// Parse and validate the token
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid token: %w", err)
	}

	// Check if the token is valid
	if !token.Valid {
		return uuid.Nil, fmt.Errorf("invalid token")
	}

	// Get the subject (user ID) from claims
	subject, err := claims.GetSubject()
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to get subject from claims: %w", err)
	}

	// Parse the subject as UUID
	userID, err := uuid.Parse(subject)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID in token: %w", err)
	}

	return userID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header not found")
	}

	// Check if the header has the Bearer prefix
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("invalid authorization header format")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", fmt.Errorf("token is empty")
	}

	return token, nil
}

func MakeRefreshToken() (string, error) {
	bytes := make([]byte, 32)

	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	token := hex.EncodeToString(bytes)

	return token, nil
}

// GetAPIKey extracts the API key from the Authorization header
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header not found")
	}

	// Check if the header has the ApiKey prefix
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "apikey" {
		return "", fmt.Errorf("invalid authorization header format")
	}

	apiKey := strings.TrimSpace(parts[1])
	if apiKey == "" {
		return "", fmt.Errorf("API key is empty")
	}

	return apiKey, nil
}
