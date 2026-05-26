package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	if token == "" {
		t.Fatal("Expected non-empty token string")
	}
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret"
	expiresIn := time.Hour

	// Create a valid token
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	// Validate the token
	validatedUserID, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Fatalf("ValidateJWT failed: %v", err)
	}

	if validatedUserID != userID {
		t.Errorf("Expected user ID %v, got %v", userID, validatedUserID)
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret"
	expiresIn := -time.Hour // Expired token (negative duration)

	// Create an expired token
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	// Validate the expired token
	_, err = ValidateJWT(token, tokenSecret)
	if err == nil {
		t.Fatal("Expected error for expired token, got nil")
	}
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret"
	wrongSecret := "wrong-secret"
	expiresIn := time.Hour

	// Create a token with the correct secret
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	// Validate with wrong secret
	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Fatal("Expected error for wrong secret, got nil")
	}
}

func TestValidateJWT_InvalidToken(t *testing.T) {
	tokenSecret := "test-secret"
	invalidToken := "invalid.token.string"

	// Validate an invalid token
	_, err := ValidateJWT(invalidToken, tokenSecret)
	if err == nil {
		t.Fatal("Expected error for invalid token, got nil")
	}
}

func TestMakeJWT_ZeroExpiration(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret"
	expiresIn := 0 * time.Second

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	if token == "" {
		t.Fatal("Expected non-empty token string for zero expiration")
	}
}
