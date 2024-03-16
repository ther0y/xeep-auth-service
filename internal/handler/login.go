package handler

import (
	"context"
	"github.com/ther0y/xeep-auth-service/auther"
)

func (s *Service) Login(ctx context.Context, req *auther.LoginRequest) (*auther.LoginResponse, error) {
	return &auther.LoginResponse{
		AuthenticationData: &auther.AuthenticationData{
			Id:           "",
			AccessToken:  "",
			RefreshToken: "",
		},
	}, nil
}
