package services

import (
	"time"

	"github.com/ther0y/xeep-auth-service/internal/database"
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

func invalidateToken(key string, expirationTime time.Time) error {
	duration := time.Until(expirationTime)

	// Set the key in the cache with the expiration time
	err := database.AddToRedis(key, "true", duration)
	if err != nil {
		return err
	}

	return nil
}

func isTokenInvalidated(key string) (bool, error) {
	data, err := database.GetFromRedis(key)
	if err != nil {
		if err.Error() == "redis: nil" {
			return false, nil
		}
		return false, err
	}

	if data != "" {
		return true, nil
	}

	return false, nil
}
