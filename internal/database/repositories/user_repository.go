package repositories

import (
	"context"

	"github.com/ther0y/xeep-auth-service/internal/database"
	"github.com/ther0y/xeep-auth-service/internal/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type UserRepository struct {
	Collection *mongo.Collection
}

func NewUserRepository() *UserRepository {
	return &UserRepository{Collection: database.UserCollection}
}

func (u *UserRepository) IsIdentifierExists(ctx context.Context, identifier string) (bool, error) {
	count, err := u.Collection.CountDocuments(ctx, bson.M{"$or": []bson.M{{"username": identifier}, {"email": identifier}, {"phone": identifier}}})
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (u *UserRepository) FindByIdentifier(ctx context.Context, identifier string) (*model.User, error) {
	user := &model.User{}

	err := u.Collection.FindOne(ctx, bson.M{"$or": []bson.M{{"username": identifier}, {"email": identifier}, {"phone": identifier}}}).Decode(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (u *UserRepository) InsertUser(ctx context.Context, newUser *model.User) (*model.User, error) {
	user := model.User{}

	res, err := u.Collection.InsertOne(ctx, newUser)
	if err != nil {
		return nil, err
	}

	err = u.Collection.FindOne(ctx, bson.M{"_id": res.InsertedID}).Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}
