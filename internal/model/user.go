package model

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/database"
	"github.com/ther0y/xeep-auth-service/internal/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var secretKey string

func init() {
	godotenv.Load(".env.local")

	secretKey = os.Getenv("SECRET_KEY")

	if secretKey == "" {
		log.Fatal("SECRET_KEY is not set")
	}
}

type User struct {
	ID              primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Username        string             `bson:"username" json:"username"`
	Email           string             `bson:"email,omitempty" json:"email"`
	Phone           string             `bson:"phone" json:"phone"`
	SmsOtp          string             `bson:"smsOtp,omitempty"`
	EmailOtp        string             `bson:"emailOtp,omitempty"`
	IsEmailVerified bool               `bson:"isEmailVerified" json:"isEmailVerified"`
	IsPhoneVerified bool               `bson:"isPhoneVerified" json:"isPhoneVerified"`
	Password        string             `bson:"password"`
	Salt            string             `bson:"salt"`
	Avatar          string             `bson:"avatar" json:"avatar"`
	CreatedAt       int64              `bson:"createdAt" json:"createdAt"`
	UpdatedAt       int64              `bson:"updatedAt" json:"updatedAt"`
	DeletedAt       int64              `bson:"deletedAt,omitempty" json:"deletedAt"`
}

func NewUser() *User {
	return &User{}
}

func (u *User) ToAutherUser() *auther.User {
	return &auther.User{
		Id:              u.ID.String(),
		Username:        u.Username,
		Email:           u.Email,
		Phone:           u.Phone,
		IsEmailVerified: u.IsEmailVerified,
		IsPhoneVerified: u.IsPhoneVerified,
		Avatar:          u.Avatar,
		CreatedAt:       u.CreatedAt,
		UpdatedAt:       u.UpdatedAt,
		DeletedAt:       u.DeletedAt,
	}
}

func (u *User) GenerateAuthToken() (string, error) {
	now := time.Now()

	authToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat":      now.Unix(),
		"exp":      now.Add(time.Hour).Unix(),
		"username": u.Username,
		"sub":      u.ID.Hex(),
		"iss":      "xeep-auth-service",
		"aud":      "xeep-auth-service",
	})

	signedAuthToken, err := authToken.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return signedAuthToken, nil
}

func (u *User) GenerateRefreshToken() (string, error) {
	now := time.Now()
	refreshId := make([]byte, 16)
	_, _ = rand.Read(refreshId)
	refreshIdString := hex.EncodeToString(refreshId)

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(time.Hour * 24 * 30).Unix(),
		"sub": u.ID.Hex(),
		"jti": refreshIdString,
		"iss": "xeep-auth-service",
		"aud": "xeep-auth-service",
	})

	signedRefreshToken, err := refreshToken.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return signedRefreshToken, nil
}

type UserTokens struct {
	AccessToken  string
	RefreshToken string
}

func (u *User) GenerateTokens() (tokens UserTokens, err error) {
	authToken, err := u.GenerateAuthToken()
	if err != nil {
		return tokens, err
	}
	tokens.AccessToken = authToken

	refreshToken, err := u.GenerateRefreshToken()
	if err != nil {
		return tokens, err
	}
	tokens.RefreshToken = refreshToken

	return tokens, nil
}

func (u *User) ComparePassword(password string) (bool, error) {
	hashedPassword, err := utils.HashPasswordWithSalt(password, u.Salt)
	if err != nil {
		return false, err
	}

	return hashedPassword == u.Password, nil
}

func (u *User) Save() error {
	filter := bson.M{"$or": []bson.M{{"_id": u.ID}, {"username": u.Username}, {"email": u.Email}, {"phone": u.Phone}}}
	update := bson.M{"$set": u}
	opts := options.Update().SetUpsert(true)

	_, err := database.UserCollection.UpdateOne(context.Background(), filter, update, opts)
	if err != nil {
		return err
	}

	err = database.UserCollection.FindOne(context.Background(), filter).Decode(u)
	if err != nil {
		return err
	}

	return nil
}

func (u *User) IsIdentifierExists(ctx context.Context, identifier string) (bool, error) {
	count, err := database.UserCollection.CountDocuments(ctx, bson.M{"$or": []bson.M{{"username": identifier}, {"email": identifier}, {"phone": identifier}}})
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (u *User) FindByIdentifier(ctx context.Context, identifier string) error {
	err := database.UserCollection.FindOne(ctx, bson.M{"$or": []bson.M{{"username": identifier}, {"email": identifier}, {"phone": identifier}}}).Decode(u)
	if err != nil {
		return err
	}

	return nil
}

func (u *User) SaveSession(key string, ip string, device string, deviceId string) (*Session, error) {
	session := &Session{
		User:      u.ID,
		Key:       key,
		IP:        ip,
		DeviceID:  deviceId,
		Device:    device,
		CreatedAt: time.Now().Unix(),
		UpdatedAt: time.Now().Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	err := session.Save()
	if err != nil {
		return nil, err
	}

	return session, nil
}
