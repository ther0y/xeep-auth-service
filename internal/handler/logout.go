package handler

import (
	"context"
	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/errors"
	"github.com/ther0y/xeep-auth-service/internal/model"
	"github.com/ther0y/xeep-auth-service/internal/services"
	"google.golang.org/grpc/metadata"
)

func (s *Service) Logout(ctx context.Context, req *auther.Empty) (*auther.SuccessResponse, error) {
	user := ctx.Value("user").(*model.User)
	if user == nil {
		return nil, errors.UnauthenticatedError("Invalid credentials")
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.UnauthenticatedError("Invalid credentials")
	}

	values := md.Get("refresh_token")
	if len(values) == 0 {
		return nil, errors.UnauthenticatedError("Invalid credentials")
	}
	refreshToken := values[0]

	claims, err := services.RefreshTokenManagerService.GetClaims(refreshToken)
	if err != nil {
		return nil, errors.UnauthenticatedError("Invalid credentials")
	}

	err = services.InvalidateSessionData(claims.SessionID, claims.ExpiresAt)
	if err != nil {
		return nil, err
	}

	return &auther.SuccessResponse{
		Success: true,
	}, nil
}

func (s *Service) LogoutAll(ctx context.Context, req *auther.Empty) (*auther.SuccessResponse, error) {
	user := ctx.Value("user").(*model.User)
	if user == nil {
		return nil, errors.UnauthenticatedError("Invalid credentials")
	}

	sessions, err := services.GetUsersSessions(user.ID.Hex())

	err = services.InvalidateAllSessionsData(sessions)
	if err != nil {
		return nil, errors.InternalError("failed to invalidate all sessions", err)
	}

	return &auther.SuccessResponse{
		Success: true,
	}, nil
}
