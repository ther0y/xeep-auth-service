package services

import (
	"fmt"
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
		return status.Error(codes.Internal, fmt.Errorf("failed to invalidate the session: %w", err).Error())
	}

	ok, _ := database.DeleteSessionByID(sessionID)
	if !ok {
		return status.Error(codes.Internal, "failed to delete the session")
	}

	err = database.DeleteSessionRevisionTracker(sessionID)
	if err != nil {
		return status.Error(codes.Internal, fmt.Errorf("failed to delete the session revision tracker: %w", err).Error())
	}

	// TODO: Notify the user about the suspicious activity

	return nil
}

func IsSessionInvalidated(sessionID string) (bool, error) {
	key := generateKey(sessionID)

	data, err := database.GetFromRedis(key)
	if err != nil {
		if err.Error() == "redis: nil" {
			return false, nil
		}
		return false, status.Error(codes.Internal, fmt.Errorf("failed to get the session invalidation tracker from db: %w", err).Error())
	}

	if data != "" {
		return true, nil
	}

	return false, nil
}
