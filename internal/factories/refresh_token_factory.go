package factories

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type RefreshToken struct {
	Id  string
	Sub string
	Iat int64
}

type RefreshTokenFactory struct{}

func (f RefreshTokenFactory) Create(userId string, iat int64) RefreshToken {
	refreshId := make([]byte, 16)
	_, _ = rand.Read(refreshId)
	refreshIdString := hex.EncodeToString(refreshId)
	now := time.Now().Unix()

	if iat != 0 {
		now = iat
	}

	return RefreshToken{
		Id:  refreshIdString,
		Sub: userId,
		Iat: now,
	}
}
