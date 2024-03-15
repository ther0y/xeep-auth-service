package main

import (
	"context"
	"github.com/ther0y/xeep-auth-service/auther"
	"google.golang.org/grpc"
	"log"
	"net"
)

type server struct {
	auther.UnimplementedAutherServer
}

func (s *server) Login(ctx context.Context, req *auther.LoginRequest) (*auther.LoginResponse, error) {
	return &auther.LoginResponse{
		AuthenticationData: &auther.AuthenticationData{
			Id:           "",
			AccessToken:  "",
			RefreshToken: "",
		},
	}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":8089")

	if err != nil {
		log.Fatalf("Failed to bind to port 8089 %s", err)
	}

	s := grpc.NewServer()
	service := &server{}

	auther.RegisterAutherServer(s, service)

	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve %s", err)
	}
}
