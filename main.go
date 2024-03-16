package main

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/ther0y/xeep-auth-service/internal/database"
	"github.com/ther0y/xeep-auth-service/internal/server"
)

func main() {
	err := godotenv.Load(".env.local")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	err = database.Init(os.Getenv("MONGO_URI"), os.Getenv("MONGO_DATABASE"))
	if err != nil {
		log.Fatalf("Failed to connect to database %s", err)
	}
	fmt.Println("Connected to mongoDB")

	defer func() {
		err := database.Close()
		if err != nil {
			log.Fatalf("Failed to close database connection %s", err)
		}
	}()

	if err := server.Init(os.Getenv("GRPC_PORT")); err != nil {
		log.Printf("Failed to start server %s", err)
	}
}
