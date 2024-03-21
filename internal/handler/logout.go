package handler

import (
	"context"
	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/model"
	"github.com/ther0y/xeep-auth-service/internal/services"
	"google.golang.org/grpc/metadata"
)

func (s *Service) Logout(ctx context.Context, req *auther.Empty) (*auther.SuccessResponse, error) {
	user := ctx.Value("user").(*model.User)
	if user == nil {
		return nil, unauthenticatedError("Invalid credentials")
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, unauthenticatedError("Invalid credentials")
	}

	values := md.Get("refresh_token")
	if len(values) == 0 {
		return nil, unauthenticatedError("Invalid credentials")
	}
	refreshToken := values[0]

	claims, err := services.RefreshTokenManagerService.GetClaims(refreshToken)
	if err != nil {
		return nil, unauthenticatedError("Invalid credentials")
	}

	err = services.InvalidateAllSessionData(claims.SessionID, claims.ExpiresAt)
	if err != nil {
		return nil, err
	}

	return &auther.SuccessResponse{
		Success: true,
	}, nil
}
