package services

import (
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

	RefreshTokenManagerService = newRefreshTokenManager(secretKey, time.Hour*24*7)
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

func newRefreshTokenManager(secretKey string, duration time.Duration) *RefreshTokenManager {
	return &RefreshTokenManager{secretKey, duration}
}

func (r *RefreshTokenManager) GenerateToken(user *model.User, sessionID string) (string, error) {
	claims := RefreshTokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(r.duration).Unix(),
			Issuer:    "xeep-auth-service",
			Audience:  "xeep-auth-service",
			IssuedAt:  time.Now().Unix(),
			Subject:   user.ID.Hex(),
		},
		Username:  user.Username,
		SessionID: sessionID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(r.secretKey))
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

	return claims, nil
}
