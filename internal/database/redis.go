package database

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	redisClient *redis.Client
)

func InitRedis(connectionString string) error {
	opt, err := redis.ParseURL(connectionString)
	if err != nil {
		panic(err)
	}

	redisClient = redis.NewClient(opt)

	err = redisClient.Ping(context.Background()).Err()
	return err
}

func CloseRedis() error {
	return redisClient.Close()
}

func AddToRedis(key string, value string, duration time.Duration) error {
	return redisClient.Set(context.Background(), key, value, duration).Err()
}

func GetFromRedis(key string) (string, error) {
	return redisClient.Get(context.Background(), key).Result()
}

func DeleteFromRedis(key string) error {
	return redisClient.Del(context.Background(), key).Err()
}
