package services

import (
	"fmt"
	"github.com/ther0y/xeep-auth-service/internal/model"
)

type UserTokens struct {
	AccessToken    string
	RefreshToken   string
	RefreshTokenID string
}

type TokenManager interface {
	GenerateToken(user *model.User) (string, error)
	VerifyToken(tokenString string) (*UserClaims, error)
}

func GenerateUserTokens(user *model.User, sessionID string) (tokens UserTokens, err error) {
	accessToken, err := AccessTokenManagerService.GenerateToken(user, sessionID)
	if err != nil {
		return tokens, fmt.Errorf("failed to generate access token: %w", err)
	}
	tokens.AccessToken = accessToken

	refreshTokenData, err := RefreshTokenManagerService.GenerateToken(user, sessionID)
	if err != nil {
		return tokens, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	tokens.RefreshToken = refreshTokenData.Token
	tokens.RefreshTokenID = refreshTokenData.ID

	return tokens, nil
}
