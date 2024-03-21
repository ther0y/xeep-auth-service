package handler

import (
	"context"
	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/model"
)

func (s *Service) Profile(ctx context.Context, req *auther.Empty) (*auther.ProfileResponse, error) {
	user, ok := ctx.Value("user").(*model.User)
	if !ok {
		return nil, unauthenticatedError("Invalid credentials")
	}

	return &auther.ProfileResponse{
		User: user.ToAutherUser(),
	}, nil
}
