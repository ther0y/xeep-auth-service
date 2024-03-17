package repositories

import (
	"context"

	"github.com/ther0y/xeep-auth-service/internal/database"
	"github.com/ther0y/xeep-auth-service/internal/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type SessionRepository struct {
	Collection *mongo.Collection
}

func NewSessionRepository() *SessionRepository {
	return &SessionRepository{Collection: database.SessionCollection}
}

func (s *SessionRepository) InsertSession(ctx context.Context, newSession *model.Session) (*model.Session, error) {
	session := model.Session{}

	res, err := s.Collection.InsertOne(ctx, newSession)
	if err != nil {
		return nil, err
	}

	err = s.Collection.FindOne(ctx, bson.M{"_id": res.InsertedID}).Decode(&session)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

func (s *SessionRepository) FindSessionByKey(ctx context.Context, key string) (*model.Session, error) {
	session := &model.Session{}

	err := s.Collection.FindOne(ctx, bson.M{"key": key}).Decode(session)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (s *SessionRepository) DeleteSession(ctx context.Context, key string) error {
	_, err := s.Collection.DeleteOne(ctx, bson.M{"key": key})
	return err
}

func (s *SessionRepository) DeleteSessionsByUserId(ctx context.Context, userId primitive.ObjectID) error {
	_, err := s.Collection.DeleteMany(ctx, bson.M{"userId": userId})
	return err
}
