package factories

import (
	"github.com/golang-jwt/jwt"
	"time"
)

type AuthTokenFactory struct{}

func (f AuthTokenFactory) Create(userId string, username string) (string, error) {
	now := time.Now()

	authToken := jwt.New(jwt.SigningMethodHS256)
	authTokenClaims := authToken.Claims.(jwt.MapClaims)

	authTokenClaims["iat"] = now.Unix()
	authTokenClaims["exp"] = now.Add(time.Hour).Unix()

	if userId != "" {
		authTokenClaims["username"] = username
		authTokenClaims["sub"] = userId
	} else {
		authTokenClaims["username"] = "guest"
	}

	signedAuthToken, err := authToken.SignedString([]byte("your-secret"))
	if err != nil {
		return "", err
	}

	return signedAuthToken, nil
}
