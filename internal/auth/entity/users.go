package entity

import (
	"time"

	"github.com/go-playground/validator/v10"
)

var validate = validator.New(validator.WithRequiredStructEnabled())

type UserAccount struct {
	Username  string `validate:"required,email"`
	Password  string `validate:"required,min=8"`
	CreatedAt time.Time
}

func NewUserAccount(username, password string) (UserAccount, error) {
	ua := UserAccount{
		Username:  username,
		Password:  password,
		CreatedAt: time.Now(),
	}
	if err := validate.Struct(ua); err != nil {
		return UserAccount{}, err
	}
	return ua, nil
}

type RegisterUserRequest struct {
	Username string
	Password string
}

type LoginUserRequest struct {
	Username string
	Password string
}
