package jwt

import "time"

type Config struct {
	Issuer           string
	AccessExpiresIn  time.Duration
	RefreshExpiresIn time.Duration
	PublicKey        []byte
	PrivateKey       []byte
}
