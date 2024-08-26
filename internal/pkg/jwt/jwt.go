package jwt

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// for now there's no reason for err segregation & uniq processing
	// but its good idea to have list of error which module can return
	ErrKeyParsing      = errors.New("parsing error")
	ErrTokenGeneration = errors.New("token generation error")
	ErrSigning         = errors.New("signing error")
	ErrValidation      = errors.New("token validation errror")
)

type JWTManager struct {
	issuer           string
	accessExpiresIn  time.Duration
	refreshExpiresIn time.Duration
	publicKey        interface{}
	privateKey       interface{}
}

func NewJWTManager(cfg Config) (*JWTManager, error) {
	pubKey, err := jwt.ParseEdPublicKeyFromPEM(cfg.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyParsing, err)
	}

	privKey, err := jwt.ParseEdPrivateKeyFromPEM(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyParsing, err)
	}

	return &JWTManager{
		issuer:           cfg.Issuer,
		accessExpiresIn:  cfg.AccessExpiresIn,
		refreshExpiresIn: cfg.RefreshExpiresIn,
		publicKey:        pubKey,
		privateKey:       privKey,
	}, nil
}

func (j *JWTManager) IssueAccessToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"iss": j.issuer,
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(j.accessExpiresIn).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(j.privateKey.(ed25519.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrSigning, err)
	}

	return signed, nil
}

func (j *JWTManager) IssueRefreshToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"iss": j.issuer,
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(j.refreshExpiresIn).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(j.privateKey.(ed25519.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrSigning, err)
	}

	return signed, nil
}

func (j *JWTManager) VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, ErrValidation
		}
		return j.publicKey, nil
	},
		jwt.WithIssuer(j.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrValidation, err)
	}

	return token, nil
}

func (j *JWTManager) RefreshExpiresDuration() time.Duration {
	return j.refreshExpiresIn
}
