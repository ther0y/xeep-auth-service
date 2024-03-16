package database

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	client            *mongo.Client
	UserCollection    *mongo.Collection
	SessionCollection *mongo.Collection
)

func Init(connectionString string, database string) error {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(connectionString))
	if err != nil {
		return err
	}

	UserCollection = client.Database(database).Collection("users")
	SessionCollection = client.Database(database).Collection("sessions")

	err = client.Database("admin").RunCommand(context.Background(), bson.D{{Key: "ping", Value: 1}}).Err()
	if err != nil {
		return err
	}

	err = setupConstraints()

	return err
}

func setupConstraints() error {
	return setupUserConstraints()
}

func Close() error {
	return client.Disconnect(context.Background())
}
