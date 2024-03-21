package services

import (
	"github.com/ther0y/xeep-auth-service/internal/database"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

func generateKey(sessionID string) string {
	return "invalidated:session:" + sessionID
}

func InvalidateAllSessionData(sessionID string, expireAt int64) error {
	expirationTime := time.Unix(expireAt, 0)

	err := database.AddSessionInvalidation(sessionID, expirationTime)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	ok, _ := database.DeleteSessionByID(sessionID)
	if !ok {
		return status.Error(codes.Internal, "failed to delete the session")
	}

	err = database.DeleteSessionRevisionTracker(sessionID)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	// TODO: Notify the user about the suspicious activity

	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	return nil
}

func IsSessionInvalidated(sessionID string) (bool, error) {
	key := generateKey(sessionID)

	data, err := database.GetFromRedis(key)
	if err != nil {
		if err.Error() == "redis: nil" {
			return false, nil
		}
		return false, err
	}

	if data != "" {
		return true, nil
	}

	return false, nil
}
