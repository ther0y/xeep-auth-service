package handler

import (
	"context"

	"github.com/ther0y/xeep-auth-service/auther"
)

func (s *Service) Profile(ctx context.Context, req *auther.Empty) (*auther.ProfileResponse, error) {
	return &auther.ProfileResponse{
		User: &auther.User{
			Id:       "123",
			Email:    "",
			Phone:    "",
			Username: "johndoe",
		},
	}, nil
}
