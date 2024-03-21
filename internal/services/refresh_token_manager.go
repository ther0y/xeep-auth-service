package services

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/ther0y/xeep-auth-service/internal/database"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"github.com/ther0y/xeep-auth-service/internal/model"
)

var (
	RefreshTokenManagerService *RefreshTokenManager
	refreshTokenDuration       = int64(30 * 60)  // 30 minutes in seconds
	refreshTokenGracePeriod    = int64(120 * 60) // 2 hours in seconds
)

func init() {
	err := godotenv.Load(".env.local")
	if err != nil {
		panic("Failed to load env file")
	}

	secretKey := os.Getenv("REFRESH_SECRET")
	if secretKey == "" {
		panic("REFRESH_SECRET is not set")
	}

	RefreshTokenManagerService = newRefreshTokenManager(secretKey)
}

type RefreshTokenManager struct {
	secretKey string
}

type RefreshTokenClaims struct {
	jwt.StandardClaims
	Username  string `json:"username,omitempty"`
	SessionID string `json:"sessionID,omitempty"`
	Revision  int    `json:"revision,omitempty"`
}

type RefreshTokenData struct {
	ID    string
	Token string
}

func newRefreshTokenManager(secretKey string) *RefreshTokenManager {
	return &RefreshTokenManager{secretKey}
}

func (r *RefreshTokenManager) GenerateToken(user *model.User, sessionID string) (refreshTokenData *RefreshTokenData, err error) {
	refreshTokenID, err := generateRandomID()
	if err != nil {
		return refreshTokenData, fmt.Errorf("failed to generate refresh token ID: %w", err)
	}

	// Get the revision number from redis or store 1 if it doesn't exist
	currentRevision, err := database.GetSessionsLatestRevision(sessionID)

	claims := RefreshTokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + refreshTokenDuration,
			Issuer:    "xeep-auth-service",
			Audience:  "xeep-auth-service",
			IssuedAt:  time.Now().Unix(),
			Subject:   user.ID.Hex(),
			Id:        refreshTokenID,
		},
		Username:  user.Username,
		SessionID: sessionID,
		Revision:  currentRevision + 1,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(r.secretKey))
	if err != nil {
		return refreshTokenData, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	err = database.IncrementSessionRevision(sessionID)
	if err != nil {
		return refreshTokenData, fmt.Errorf("failed to increment session revision: %w", err)
	}

	return &RefreshTokenData{refreshTokenID, tokenString}, nil
}

func (r *RefreshTokenManager) GetClaims(tokenString string) (*RefreshTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(r.secretKey), nil
	})

	if err != nil {
		return handleTokenError(err, token)
	}

	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func generateRandomID() (string, error) {
	// Generate a random byte slice with 32 bytes
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random ID: %w", err)
	}

	// Encode the random bytes to base64 string
	randomID := base64.URLEncoding.EncodeToString(randomBytes)

	return randomID, nil
}

func handleTokenError(err error, token *jwt.Token) (*RefreshTokenClaims, error) {
	var validationError *jwt.ValidationError
	if errors.As(err, &validationError) {
		if validationError.Errors&jwt.ValidationErrorExpired != 0 {
			return handleExpiredToken(token)
		}
		// Handle other validation errors
		return nil, err
	}
	// Handle non-validation errors
	return nil, err
}

func handleExpiredToken(token *jwt.Token) (*RefreshTokenClaims, error) {
	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	now := time.Now().Unix()
	if now <= claims.ExpiresAt+refreshTokenGracePeriod {
		// Token is within the grace period. You may choose to proceed.
		return claims, nil
	}

	// Token is expired and outside the grace period.
	return nil, fmt.Errorf("token is expired, including the grace period")
}
