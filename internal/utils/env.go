package utils

import (
	"github.com/joho/godotenv"
	"os"
)

func GetEnv(key string) (string, error) {
	err := godotenv.Load(".env.local")

	if err != nil {
		return "", err
	}

	return os.Getenv(key), nil
}
