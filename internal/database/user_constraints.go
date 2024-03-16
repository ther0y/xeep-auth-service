package database

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func setupUserConstraints() error {
	// Create unique indexes for username, email and phone fields in users collection
	_, err := UserCollection.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.M{
			"username": 1,
		},
		Options: options.Index().SetUnique(true).SetSparse(true),
	})
	if err != nil {
		return err
	}

	_, err = UserCollection.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.M{
			"email": 1,
		},
		Options: options.Index().SetUnique(true).SetSparse(true),
	})
	if err != nil {
		return err
	}

	_, err = UserCollection.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.M{
			"phone": 1,
		},
		Options: options.Index().SetUnique(true).SetSparse(true),
	})
	if err != nil {
		return err
	}

	return nil
}
