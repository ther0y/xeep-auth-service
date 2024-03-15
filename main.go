package main

import (
	"github.com/ther0y/xeep-auth-service/auther"
	autherservice "github.com/ther0y/xeep-auth-service/service"
	"google.golang.org/grpc"
	"log"
	"net"
)

func main() {
	lis, err := net.Listen("tcp", ":8089")

	if err != nil {
		log.Fatalf("Failed to bind to port 8089 %s", err)
	}

	s := grpc.NewServer()
	service := &autherservice.Service{}

	auther.RegisterAutherServer(s, service)

	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve %s", err)
	}
}
