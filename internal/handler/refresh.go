package handler

import (
	"context"
	"github.com/ther0y/xeep-auth-service/internal/errors"

	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/model"
	"github.com/ther0y/xeep-auth-service/internal/services"
)

func (s *Service) Refresh(ctx context.Context, req *auther.Empty) (*auther.AuthenticationData, error) {
	user := ctx.Value("user").(*model.User)
	if user == nil {
		return nil, errors.UnauthenticatedError("Invalid credentials")
	}

	session := ctx.Value("session").(*model.Session)
	if session == nil {
		return nil, errors.UnauthenticatedError("Invalid credentials")
	}

	tokens, err := services.GenerateUserTokens(user, session.ID.Hex())
	if err != nil {
		return nil, errors.InternalError("failed to generate the tokens", err)
	}

	return &auther.AuthenticationData{
		Id:           user.ID.Hex(),
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}
