package model

import (
	"context"

	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/database"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Session struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	User      primitive.ObjectID `bson:"userId" json:"userId"`
	Key       string             `bson:"key" json:"key"`
	IP        string             `bson:"ip" json:"ip"`
	DeviceID  string             `bson:"deviceId" json:"deviceId"`
	Device    string             `bson:"device" json:"device"`
	CreatedAt int64              `bson:"createdAt" json:"createdAt"`
	UpdatedAt int64              `bson:"updatedAt" json:"updatedAt"`
	DeletedAt int64              `bson:"deletedAt,omitempty" json:"deletedAt"`
	IssuedAt  int64              `bson:"issuedAt" json:"issuedAt"`
}

func NewSession() *Session {
	return &Session{}
}

func (s *Session) ToAutherSession() *auther.Session {
	return &auther.Session{
		Id:        s.ID.String(),
		UserId:    s.User.String(),
		Key:       s.Key,
		Ip:        s.IP,
		DeviceId:  s.DeviceID,
		Device:    s.Device,
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt,
		DeletedAt: s.DeletedAt,
		IssuedAt:  s.IssuedAt,
	}
}

func (s *Session) Save() error {
	filter := bson.M{"$or": []bson.M{{"_id": s.ID}, {"key": s.Key}}}
	update := bson.M{"$set": s}
	opts := options.Update().SetUpsert(true)

	_, err := database.SessionCollection.UpdateOne(context.Background(), filter, update, opts)
	if err != nil {
		return err
	}

	err = database.SessionCollection.FindOne(context.Background(), filter).Decode(s)
	if err != nil {
		return err
	}

	return nil
}
