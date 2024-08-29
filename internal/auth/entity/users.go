package entity

import (
	"time"
)

type UserAccount struct {
	Username       string
	HashedPassword string
	CreatedAt      time.Time
}

func NewUserAccount(username, hashedPassword string) (UserAccount, error) {
	ua := UserAccount{
		Username:       username,
		HashedPassword: hashedPassword,
		CreatedAt:      time.Now(),
	}
	return ua, nil
}
