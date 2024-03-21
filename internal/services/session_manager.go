package services

import (
	"context"
	"fmt"
	"github.com/ther0y/xeep-auth-service/internal/database"
	"github.com/ther0y/xeep-auth-service/internal/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

func generateKey(sessionID string) string {
	return "invalidated:session:" + sessionID
}

func InvalidateSessionData(sessionID string, expireAt int64) error {
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

func InvalidateAllSessionsData(sessionsIDs []string) error {
	for _, sessionID := range sessionsIDs {
		err := InvalidateSessionData(sessionID, time.Now().Add(time.Hour*2).Unix())
		if err != nil {
			return err
		}
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
		return false, status.Error(codes.Internal, fmt.Errorf("failed to get the session invalidation tracker from db: %w", err).Error())
	}

	if data != "" {
		return true, nil
	}

	return false, nil
}

func GetUsersSessions(userID string) ([]string, error) {
	userObjectId, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Errorf("failed to convert user id to object id: %w", err).Error())
	}

	filter := bson.M{"userId": userObjectId}
	cursor, err := database.SessionCollection.Find(context.Background(), filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get users sessions: %w", err)
	}

	var sessions []string
	for cursor.Next(context.Background()) {
		var session model.Session
		err := cursor.Decode(&session)
		if err != nil {
			return nil, fmt.Errorf("failed to decode session: %w", err)
		}

		sessions = append(sessions, session.ID.Hex())
	}

	return sessions, nil
}
