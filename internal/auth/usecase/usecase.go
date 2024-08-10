package usecase

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/Karzoug/innopolis-auth-go/internal/auth/entity"
	"github.com/Karzoug/innopolis-auth-go/internal/auth/repository"
	"github.com/Karzoug/innopolis-auth-go/internal/buildinfo"
	"github.com/Karzoug/innopolis-auth-go/internal/gateway/http/gen"
	"github.com/golang-jwt/jwt/v5"
)

type UserRepository interface {
	RegisterUser(ctx context.Context, u entity.UserAccount) error
	FindUserByEmail(ctx context.Context, username string) (entity.UserAccount, error)
}

type TokenRepository interface {
	Get(key string) (string, bool)
	Set(key string, value string, duration time.Duration)
	Delete(key string)
}

type CryptoPassword interface {
	HashPassword(password string) ([]byte, error)
	ComparePasswords(fromUser, fromDB string) bool
}

type JWTManager interface {
	RefreshExpiresDuration() time.Duration
	IssueAccessToken(userID string) (string, error)
	IssueRefreshToken(userID string) (string, error)
	VerifyToken(tokenString string) (*jwt.Token, error)
}

type AuthUseCase struct {
	userRepo       UserRepository
	tokenRepo      TokenRepository
	cryptoPassword CryptoPassword
	jwtManager     JWTManager
	buildInfo      buildinfo.BuildInfo
	logger         *slog.Logger
}

func NewUseCase(
	ur UserRepository,
	tr TokenRepository,
	cp CryptoPassword,
	jm JWTManager,
	bi buildinfo.BuildInfo,
	logger *slog.Logger,
) AuthUseCase {
	logger = logger.With(slog.String("from", "auth usecase"))
	return AuthUseCase{
		userRepo:       ur,
		tokenRepo:      tr,
		cryptoPassword: cp,
		jwtManager:     jm,
		buildInfo:      bi,
		logger:         logger,
	}
}

func (u AuthUseCase) PostLogin(ctx context.Context, request gen.PostLoginRequestObject) (gen.PostLoginResponseObject, error) {
	user, err := u.userRepo.FindUserByEmail(ctx, request.Body.Username)
	if err != nil {
		if errors.Is(err, repository.ErrRecordNotFound) {
			return gen.PostLogin401JSONResponse{Error: "unauthenticated"}, nil
		}
		u.logger.Warn("post login", slog.String("error", err.Error()))
		return gen.PostLogin500JSONResponse{}, nil
	}

	if !u.cryptoPassword.ComparePasswords(user.Password, request.Body.Password) {
		return gen.PostLogin401JSONResponse{Error: "unauthenticated"}, nil
	}

	accessToken, err := u.jwtManager.IssueAccessToken(user.Username)
	if err != nil {
		u.logger.Error("post login", slog.String("error", err.Error()))
		return gen.PostLogin500JSONResponse{}, err
	}
	refreshToken, err := u.jwtManager.IssueRefreshToken(user.Username)
	if err != nil {
		u.logger.Error("post login", slog.String("error", err.Error()))
		return gen.PostLogin500JSONResponse{}, err
	}

	// we use only one refresh token, so we just replace the old one or create a new one
	u.tokenRepo.Set(user.Username, getTokenSignature(refreshToken), u.jwtManager.RefreshExpiresDuration())

	return gen.PostLogin200JSONResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (u AuthUseCase) PostRegister(ctx context.Context, request gen.PostRegisterRequestObject) (gen.PostRegisterResponseObject, error) {
	hashedPassword, err := u.cryptoPassword.HashPassword(request.Body.Password)
	if err != nil {
		u.logger.Error("post register", slog.String("error", err.Error()))
		return gen.PostRegister500JSONResponse{}, nil
	}

	user, err := entity.NewUserAccount(request.Body.Username, string(hashedPassword))
	if err != nil {
		return gen.PostRegister400JSONResponse{Error: err.Error()}, nil
	}

	err = u.userRepo.RegisterUser(ctx, user)
	if err != nil {
		if errors.Is(err, repository.ErrAlreadyExists) {
			return gen.PostRegister409JSONResponse{Error: "user already exists"}, nil
		}
		u.logger.Warn("post register", slog.String("error", err.Error()))
		return gen.PostRegister500JSONResponse{}, nil
	}
	return gen.PostRegister201JSONResponse{
		Username: request.Body.Username,
	}, nil
}

func (u AuthUseCase) PostRefresh(ctx context.Context, request gen.PostRefreshRequestObject) (gen.PostRefreshResponseObject, error) {
	token, err := u.jwtManager.VerifyToken(request.Body.RefreshToken)
	if err != nil {
		return gen.PostRefresh401JSONResponse{Error: "unauthenticated"}, nil
	}

	username, err := token.Claims.GetSubject()
	if err != nil {
		return gen.PostRefresh401JSONResponse{Error: "unauthenticated"}, nil
	}
	if signature, exists := u.tokenRepo.Get(username); !exists || signature != getTokenSignature(request.Body.RefreshToken) {
		return gen.PostRefresh401JSONResponse{Error: "unauthenticated"}, nil
	}

	accessToken, err := u.jwtManager.IssueAccessToken(username)
	if err != nil {
		u.logger.Error("post refresh", slog.String("error", err.Error()))
		return gen.PostRefresh500JSONResponse{}, err
	}

	return gen.PostRefresh200JSONResponse{
		AccessToken: accessToken,
	}, nil
}

func (u AuthUseCase) GetBuildinfo(ctx context.Context, request gen.GetBuildinfoRequestObject) (gen.GetBuildinfoResponseObject, error) {
	return gen.GetBuildinfo200JSONResponse{
		Arch:       u.buildInfo.Arch,
		BuildDate:  u.buildInfo.BuildDate,
		CommitHash: u.buildInfo.CommitHash,
		Compiler:   u.buildInfo.Compiler,
		GoVersion:  u.buildInfo.GoVersion,
		Os:         u.buildInfo.OS,
		Version:    u.buildInfo.Version,
	}, nil
}

func getTokenSignature(token string) string {
	return token[strings.LastIndexByte(token, '.')+1:]
}
