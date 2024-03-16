package server

import (
	"fmt"
	"net"

	"github.com/ther0y/xeep-auth-service/auther"
	autherservice "github.com/ther0y/xeep-auth-service/internal/handler"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func Init(port string) error {
	address := ":" + port

	lis, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	s := grpc.NewServer()
	service := &autherservice.Service{}

	auther.RegisterAutherServer(s, service)

	fmt.Println("Server started at " + address)

	reflection.Register(s)

	if err := s.Serve(lis); err != nil {
		return err
	}
	return nil
}
