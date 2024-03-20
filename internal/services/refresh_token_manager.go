package services

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"github.com/ther0y/xeep-auth-service/internal/model"
)

var RefreshTokenManagerService *RefreshTokenManager

func init() {
	err := godotenv.Load(".env.local")
	if err != nil {
		panic("Failed to load env file")
	}

	secretKey := os.Getenv("REFRESH_SECRET")
	if secretKey == "" {
		panic("REFRESH_SECRET is not set")
	}

	RefreshTokenManagerService = newRefreshTokenManager(secretKey, time.Second*10)
}

type RefreshTokenManager struct {
	secretKey string
	duration  time.Duration
}

type RefreshTokenClaims struct {
	jwt.StandardClaims
	Username  string `json:"username"`
	SessionID string `json:"sessionID"`
}

type RefreshTokenData struct {
	ID    string
	Token string
}

func newRefreshTokenManager(secretKey string, duration time.Duration) *RefreshTokenManager {
	return &RefreshTokenManager{secretKey, duration}
}

func (r *RefreshTokenManager) GenerateToken(user *model.User) (refreshTokenData *RefreshTokenData, err error) {
	refreshTokenID, err := generateRandomID()
	if err != nil {
		return refreshTokenData, err
	}

	claims := RefreshTokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(r.duration).Unix(),
			Issuer:    "xeep-auth-service",
			Audience:  "xeep-auth-service",
			IssuedAt:  time.Now().Unix(),
			Subject:   user.ID.Hex(),
			Id:        refreshTokenID,
		},
		Username: user.Username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(r.secretKey))
	if err != nil {
		return refreshTokenData, err
	}

	return &RefreshTokenData{refreshTokenID, tokenString}, nil
}

func (r *RefreshTokenManager) VerifyToken(tokenString string) (*RefreshTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, jwt.ErrSignatureInvalid
		}

		return []byte(r.secretKey), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok {
		return nil, err
	}

	if claims.Issuer != "xeep-auth-service" {
		return nil, fmt.Errorf("invalid token issuer")
	}

	if claims.Audience != "xeep-auth-service" {
		return nil, fmt.Errorf("invalid token audience")
	}

	if claims.Subject == "" {
		return nil, fmt.Errorf("invalid token subject")
	}

	if claims.Id == "" {
		return nil, fmt.Errorf("invalid token id")
	}

	return claims, nil
}

func generateRandomID() (string, error) {
	// Generate a random byte slice with 32 bytes
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Encode the random bytes to base64 string
	randomID := base64.URLEncoding.EncodeToString(randomBytes)

	return randomID, nil
}
