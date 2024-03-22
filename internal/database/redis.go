package database

import (
	"context"
	"errors"
	"strconv"
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

func GetSessionsLatestRevision(sessionID string) (int, error) {
	key := "revision:" + sessionID

	revision, err := redisClient.Get(context.Background(), key).Result()
	if err != nil {
		revision = "0"
		redisClient.Set(context.Background(), key, revision, 0)
	}

	return strconv.Atoi(revision)
}

func IncrementSessionRevision(sessionID string) error {
	key := "revision:" + sessionID

	_, err := redisClient.Incr(context.Background(), key).Result()
	return err
}

func AddSessionInvalidation(sessionID string, expirationTime time.Time) error {
	key := "invalidated:session:" + sessionID

	return AddToRedis(key, "true", time.Until(expirationTime))
}

func DeleteSessionRevisionTracker(sessionID string) error {
	key := "revision:" + sessionID

	_, err := redisClient.Del(context.Background(), key).Result()
	return err
}

func StoreHashedSmsOtp(phone string, otp string) error {
	key := "otp:sms:" + phone

	// TODO: put the expiration time in a config file
	return AddToRedis(key, otp, time.Minute*2)
}

func CompareHashedSmsOtp(phone string, hashedSentOtp string) (bool, error) {
	key := "otp:sms:" + phone

	hashedOtp, err := GetFromRedis(key)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}

		return false, err
	}

	return hashedOtp == hashedSentOtp, nil
}

func DeleteHashedSmsOtp(phone string) error {
	key := "otp:sms:" + phone

	return DeleteFromRedis(key)
}

func StoreOtpValidationKey(phone string, validationKey string) error {
	key := "otp:sms:validation:" + phone

	return AddToRedis(key, validationKey, time.Hour*2)
}
