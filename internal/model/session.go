package model

import (
	"github.com/ther0y/xeep-auth-service/auther"
	"go.mongodb.org/mongo-driver/bson/primitive"
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
