package services

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"github.com/ther0y/xeep-auth-service/internal/model"
)

type AccessTokenManager struct {
	secretKey string
	duration  time.Duration
}

type UserClaims struct {
	jwt.StandardClaims
	Username        string   `json:"username"`
	Email           string   `json:"email"`
	IsEmailVerified bool     `json:"isEmailVerified"`
	IsPhoneVerified bool     `json:"isPhoneVerified"`
	Roles           []string `json:"roles"`
}

var AccessTokenManagerService *AccessTokenManager

func init() {
	err := godotenv.Load(".env.local")
	if err != nil {
		panic("Failed to load env file")
	}

	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		panic("SECRET_KEY is not set")
	}

	AccessTokenManagerService = &AccessTokenManager{
		secretKey: secretKey,
		duration:  time.Minute * 15,
	}
}

func (j *AccessTokenManager) GenerateToken(user *model.User) (string, error) {
	claims := UserClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(j.duration).Unix(),
			Issuer:    "xeep-auth-service",
			Audience:  "xeep-auth-service",
			IssuedAt:  time.Now().Unix(),
			Subject:   user.ID.Hex(),
		},
		Username:        user.Username,
		Email:           user.Email,
		IsEmailVerified: user.IsEmailVerified,
		IsPhoneVerified: user.IsPhoneVerified,

		//TODO: Add roles
		Roles: []string{"user"},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.secretKey))
}

func (j *AccessTokenManager) VerifyToken(tokenString string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, jwt.ErrSignatureInvalid
		}

		return []byte(j.secretKey), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*UserClaims)
	if ok && token.Valid {
		return claims, nil
	}

	return nil, err
}

func (j *AccessTokenManager) generateInvalidationKey(tokenString string) string {
	return "invalidated:accessToken:" + tokenString
}

func (j *AccessTokenManager) IsTokenInvalidated(tokenString string) (bool, error) {
	key := j.generateInvalidationKey(tokenString)

	return isTokenInvalidated(key)
}

func (j *AccessTokenManager) InvalidateToken(tokenString string) error {
	key := j.generateInvalidationKey(tokenString)

	//converts token string to jwt and detects expiration time
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(j.secretKey), nil
	})
	if err != nil {
		return err
	}

	if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
		expirationTime := time.Unix(claims.ExpiresAt, 0)
		return invalidateToken(key, expirationTime)
	} else {
		return fmt.Errorf("invalid token")
	}
}
