package handler

import (
	"context"

	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/model"
	"github.com/ther0y/xeep-auth-service/internal/services"
)

func (s *Service) Refresh(ctx context.Context, req *auther.Empty) (*auther.AuthenticationData, error) {
	user := ctx.Value("user").(*model.User)
	if user == nil {
		return nil, unauthenticatedError("Invalid credentials")
	}

	session := ctx.Value("session").(*model.Session)
	if session == nil {
		return nil, unauthenticatedError("Invalid credentials")
	}

	tokens, err := services.GenerateUserTokens(user, session.ID.Hex())
	if err != nil {
		return nil, internalError(err.Error())
	}

	return &auther.AuthenticationData{
		Id:           user.ID.Hex(),
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}
