package services

import "github.com/ther0y/xeep-auth-service/internal/model"

type UserTokens struct {
	AccessToken    string
	RefreshToken   string
	RefreshTokenID string
}

type TokenManager interface {
	GenerateToken(user *model.User) (string, error)
	VerifyToken(tokenString string) (*UserClaims, error)
}

func GenerateUserTokens(user *model.User) (tokens UserTokens, err error) {
	accessToken, err := AccessTokenManagerService.GenerateToken(user)
	if err != nil {
		return tokens, err
	}
	tokens.AccessToken = accessToken

	refreshTokenData, err := RefreshTokenManagerService.GenerateToken(user)
	if err != nil {
		return tokens, err
	}
	tokens.RefreshToken = refreshTokenData.Token
	tokens.RefreshTokenID = refreshTokenData.ID

	return tokens, nil
}
