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
	refreshtoken := values[0]

	err := services.RefreshTokenManagerService.InvalidateToken(refreshtoken)
	if err != nil {
		return nil, internalError(err.Error())
	}

	values = md.Get("access_token")
	if len(values) == 0 {
		return nil, unauthenticatedError("Invalid credentials")
	}
	accesstoken := values[0]

	// TODO: Check tokens being for same user

	err = services.AccessTokenManagerService.InvalidateToken(accesstoken)
	if err != nil {
		return nil, internalError(err.Error())
	}

	return &auther.SuccessResponse{
		Success: true,
	}, nil
}
