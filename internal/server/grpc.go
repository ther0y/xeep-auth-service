package server

import (
	"fmt"
	"net"

	"github.com/ther0y/xeep-auth-service/auther"
	autherservice "github.com/ther0y/xeep-auth-service/internal/handler"
	"github.com/ther0y/xeep-auth-service/internal/services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var accecibleRoles = map[string][]string{
	"/Auther/Profile":   {"admin", "user"},
	"/Auther/Sessions":  {"admin", "user"},
	"/Auther/Logout":    {"admin", "user"},
	"/Auther/LogoutAll": {"admin", "user"},
}

var refreshableRoles = map[string][]string{
	"/Auther/Refresh": {"admin", "user"},
}

func Init(port string) error {
	address := ":" + port

	lis, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	authInterceptor := services.NewAuthInterceptor(accecibleRoles)
	refInterceptor := services.NewRefreshInterceptor(refreshableRoles)

	s := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			authInterceptor.Unary(),
			refInterceptor.Unary(),
		),
	)

	service := &autherservice.Service{}

	auther.RegisterAutherServer(s, service)

	fmt.Println("Server started at " + address)

	reflection.Register(s)

	if err := s.Serve(lis); err != nil {
		return err
	}
	return nil
}
