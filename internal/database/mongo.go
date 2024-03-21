package database

import (
	"context"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	mongoClient       *mongo.Client
	UserCollection    *mongo.Collection
	SessionCollection *mongo.Collection
)

func InitMongo(connectionString string, database string) error {
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

func DeleteSessionByID(sessionId string) (bool, error) {
	objectID, err := primitive.ObjectIDFromHex(sessionId)
	if err != nil {
		return false, err
	}

	filter := bson.M{"_id": objectID}

	_, err = SessionCollection.DeleteOne(context.Background(), filter, nil)
	if err != nil {
		return false, err
	}

	return true, nil
}

func CloseMongo() error {
	return mongoClient.Disconnect(context.Background())
}
