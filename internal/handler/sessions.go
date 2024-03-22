package handler

import (
	"context"
	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/database"
	"github.com/ther0y/xeep-auth-service/internal/errors"
	"github.com/ther0y/xeep-auth-service/internal/model"
)

func (s *Service) Sessions(ctx context.Context, req *auther.Empty) (*auther.SessionsResponse, error) {
	user := ctx.Value("user").(*model.User)
	if user == nil {
		return nil, errors.UnauthenticatedError("Invalid credentials")
	}

	sessionsCur, err := database.SessionCollection.Find(ctx, map[string]interface{}{
		"userId": user.ID,
	})

	if err != nil {
		return nil, errors.InternalError("failed to get sessions", err)
	}

	sessions := make([]*auther.Session, 0)

	for sessionsCur.Next(ctx) {
		var session model.Session
		err := sessionsCur.Decode(&session)
		if err != nil {
			return nil, errors.InternalError("failed to decode session", err)
		}

		sessions = append(sessions, &auther.Session{
			Id:        session.ID.Hex(),
			Key:       session.Key,
			Ip:        session.IP,
			DeviceId:  session.DeviceID,
			Device:    session.Device,
			UserId:    session.User.Hex(),
			CreatedAt: session.CreatedAt,
			UpdatedAt: session.UpdatedAt,
			DeletedAt: session.DeletedAt,
			IssuedAt:  session.IssuedAt,
		})
	}

	return &auther.SessionsResponse{
		Sessions: sessions,
	}, nil
}
