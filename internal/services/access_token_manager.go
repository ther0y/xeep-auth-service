package services

import (
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"github.com/ther0y/xeep-auth-service/internal/model"
	"github.com/ther0y/xeep-auth-service/internal/utils"
	"os"
	"time"
)

var (
	AccessTokenManagerService *AccessTokenManager
	accessTokenDuration       = int64(15 * 60) // 15 minutes in seconds
)

type AccessTokenManager struct {
	secretKey string
}

type SessionClaims struct {
	jwt.StandardClaims
	SessionID string `json:"sessionID"`
}

type UserClaims struct {
	Username        string   `json:"username"`
	Email           string   `json:"email"`
	IsEmailVerified bool     `json:"isEmailVerified"`
	IsPhoneVerified bool     `json:"isPhoneVerified"`
	Roles           []string `json:"roles"`
	SessionClaims
}

func init() {
	err := godotenv.Load(".env.local")
	if err != nil {
		panic("Failed to load env file")
	}

	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		panic("SECRET_KEY is not set")
	}

	AccessTokenManagerService = &AccessTokenManager{
		secretKey: secretKey,
	}
}

func (j *AccessTokenManager) GenerateToken(user *model.User, sessionID string) (string, error) {
	tokenIssuer, err := utils.GetEnv("TOKEN_ISSUER")
	if err != nil {
		return "", fmt.Errorf("failed to get token issuer: %w", err)
	}

	tokenAudience, err := utils.GetEnv("TOKEN_AUDIENCE")
	if err != nil {
		return "", fmt.Errorf("failed to get token audience: %w", err)
	}

	claims := UserClaims{
		Username:        user.Username,
		Email:           user.Email,
		IsEmailVerified: user.IsEmailVerified,
		IsPhoneVerified: user.IsPhoneVerified,

		//TODO: Add roles
		Roles: []string{"user"},
		SessionClaims: SessionClaims{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Unix() + accessTokenDuration,
				Issuer:    tokenIssuer,
				Audience:  tokenAudience,
				IssuedAt:  time.Now().Unix(),
				Subject:   user.ID.Hex(),
			},

			SessionID: sessionID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.secretKey))
}

func (j *AccessTokenManager) GetClaims(tokenString string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, jwt.ErrSignatureInvalid
		}

		return []byte(j.secretKey), nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
