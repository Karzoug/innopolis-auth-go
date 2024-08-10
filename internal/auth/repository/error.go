package repository

import "errors"

var (
	ErrRecordNotFound = errors.New("record not found")
	ErrAlreadyExists  = errors.New("already exists")
)
