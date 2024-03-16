package model

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"github.com/ther0y/xeep-auth-service/auther"
	"go.mongodb.org/mongo-driver/bson/primitive"
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

	authToken := jwt.New(jwt.SigningMethodHS256)
	authTokenClaims := authToken.Claims.(jwt.MapClaims)

	authTokenClaims["iat"] = now.Unix()
	authTokenClaims["exp"] = now.Add(time.Hour).Unix()

	authTokenClaims["username"] = u.Username
	authTokenClaims["sub"] = u.ID.Hex()
	authTokenClaims["iss"] = "xeep-auth-service"
	authTokenClaims["aud"] = "xeep-auth-service"

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

	refreshToken := jwt.New(jwt.SigningMethodHS256)
	refreshTokenClaims := refreshToken.Claims.(jwt.MapClaims)

	refreshTokenClaims["iat"] = now.Unix()
	refreshTokenClaims["exp"] = now.Add(time.Hour * 24 * 30).Unix()

	refreshTokenClaims["sub"] = u.ID.Hex()
	refreshTokenClaims["jti"] = refreshIdString
	refreshTokenClaims["iss"] = "xeep-auth-service"
	refreshTokenClaims["aud"] = "xeep-auth-service"

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

func (u *User) GenerateTokens() (*UserTokens, error) {
	authToken, err := u.GenerateAuthToken()
	if err != nil {
		return nil, err
	}

	refreshToken, err := u.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	return &UserTokens{
		AccessToken:  authToken,
		RefreshToken: refreshToken,
	}, nil
}
