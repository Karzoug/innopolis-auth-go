package test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Karzoug/innopolis-auth-go/cmd/commands"
	"github.com/Karzoug/innopolis-auth-go/config"
	"github.com/Karzoug/innopolis-auth-go/internal/auth/repository"
	"github.com/Karzoug/innopolis-auth-go/internal/auth/usecase"
	"github.com/Karzoug/innopolis-auth-go/internal/buildinfo"
	gwHttp "github.com/Karzoug/innopolis-auth-go/internal/gateway/http"
	"github.com/Karzoug/innopolis-auth-go/internal/gateway/http/gen"
	"github.com/Karzoug/innopolis-auth-go/internal/pkg/crypto"
	"github.com/Karzoug/innopolis-auth-go/internal/pkg/jwt"
	"github.com/Karzoug/innopolis-auth-go/internal/pkg/slogtest"

	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/suite"
)

type authSuite struct {
	suite.Suite

	// suite level
	logger         *slog.Logger
	cfg            *config.Config
	passwordHasher crypto.PasswordHasher
	jwtManager     *jwt.JWTManager
	client         *resty.Client
	suiteClosers   []func() error

	// test level, fields could be grouped and stored in thread safe structure to run tests in parallel
	userRepo    repository.SQLLiteStorage
	tokenRepo   usecase.TokenRepository
	httpAddress string
	testClosers []func() error
}

func TestAuthSuite(t *testing.T) {
	suite.Run(t, new(authSuite))
}

func (s *authSuite) SetupSuite() {
	s.logger = slogtest.NullLogger()

	if err := os.Mkdir("testdir", 0750); err != nil {
		if !os.IsExist(err) {
			s.Require().NoError(err)
		} else {
			s.Require().NoError(os.RemoveAll("testdir"))
			s.Require().NoError(os.Mkdir("testdir", 0750))
		}
	}
	s.T().Log("created testdir")
	deleteTempDirFn := func() error {
		return os.RemoveAll("testdir")
	}
	s.suiteClosers = append(s.suiteClosers, deleteTempDirFn)

	var err error
	// if something goes wrong in this setup function we need to remove temp dir
	defer func() {
		if err != nil {
			s.Assert().NoError(deleteTempDirFn())
		}
	}()

	err = commands.GenerateAndSaveKeys("testdir/jwtRS256.key")
	s.Require().NoError(err)
	s.T().Log("generated crypto keys")

	s.cfg, err = config.Parse("config.yaml")
	s.Require().NoError(err)

	s.passwordHasher = crypto.NewPasswordHasher()
	s.jwtManager, err = jwt.NewJWTManager(jwt.Config{
		Issuer:           s.cfg.JWT.Issuer,
		AccessExpiresIn:  s.cfg.JWT.AccessExpiresIn,
		RefreshExpiresIn: s.cfg.JWT.RefreshExpiresIn,
		PublicKey:        []byte(s.cfg.JWT.PublicKey),
		PrivateKey:       []byte(s.cfg.JWT.PrivateKey),
	})
	s.Require().NoError(err)

	s.client = resty.New()
}

func (s *authSuite) TearDownSuite() {
	for _, c := range s.suiteClosers {
		s.Assert().NoError(c())
	}
}

func (s *authSuite) SetupTest() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	port, err := getFreePort()
	s.Require().NoError(err, "unable to get free port")
	s.cfg.HTTPServer.Address = fmt.Sprintf(":%d", port)
	s.T().Log("found free port", port)

	s.userRepo, err = repository.New(ctx, s.cfg.Storage.SQLitePath)
	s.Require().NoError(err)
	s.testClosers = append(s.testClosers, func() error {
		return s.userRepo.Close() // might be not necessary, need to check
	})
	s.T().Log("created sqlite memory storage")

	s.tokenRepo = repository.NewRWMap[string, string](s.cfg.TokenStorage.CleaningInterval)
	useCase := usecase.NewUseCase(&s.userRepo,
		s.tokenRepo,
		s.passwordHasher,
		s.jwtManager,
		buildinfo.New(),
		s.logger)

	httpServer := gwHttp.NewAuthServer(s.cfg.HTTPServer, useCase)
	s.testClosers = append(s.testClosers, func() error {
		return httpServer.Shutdown(ctx)
	})
	go func() {
		err := httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			s.T().Log("http server error: " + err.Error())
		}
	}()
	s.httpAddress = fmt.Sprintf("http://localhost:%d", port)

	// wait server ready
	err = waitServer(s.httpAddress)
	s.Require().NoError(err)
	s.T().Log("http server ready")
}

func (s *authSuite) TearDownTest() {
	for _, c := range s.testClosers {
		s.Assert().NoError(c())
	}
	s.testClosers = s.testClosers[:0]
}

func (s *authSuite) TestRegisterUser() {
	tests := []struct {
		name        string
		body        gen.RegisterUserRequest
		statusCode  int
		resUsername string
	}{
		{
			name: "normal",
			body: gen.RegisterUserRequest{
				Password: "rLymjiwoseg",
				Username: "user@example.com",
			},
			statusCode:  http.StatusCreated,
			resUsername: "user@example.com",
		},
		{
			name: "user already exists",
			body: gen.RegisterUserRequest{
				Password: "rLymjiwosegnwern",
				Username: "user@example.com",
			},
			statusCode: http.StatusConflict,
		},
		{
			name: "bad email",
			body: gen.RegisterUserRequest{
				Password: "rLy_5tr0nG!",
				Username: "user",
			},
			statusCode: http.StatusBadRequest,
		},
		{
			name: "bad password: too short",
			body: gen.RegisterUserRequest{
				Password: "rLy",
				Username: "use2r@example.com",
			},
			statusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			resp, err := s.client.R().
				SetBody(tt.body).
				SetResult(&gen.RegisterUserResponse{}).
				SetError(&gen.ErrorResponse{}).
				Post(s.httpAddress + "/register")

			s.Require().NoError(err)
			s.Require().Equal(tt.statusCode, resp.StatusCode(), resp.Error())

			if tt.statusCode >= 300 {
				return
			}
			res := resp.Result().(*gen.RegisterUserResponse)
			s.Equal(tt.resUsername, res.Username)

		})
	}
}

func (s *authSuite) TestRegisterLoginUser() {
	// register one user to test login
	const (
		password = "rLymjiwosegnwern"
		email    = "user@example.com"
	)
	resp, err := s.client.R().
		SetBody(gen.RegisterUserRequest{
			Password: password,
			Username: email,
		}).
		SetResult(&gen.RegisterUserResponse{}).
		SetError(&gen.ErrorResponse{}).
		Post(s.httpAddress + "/register")

	s.Require().NoError(err)
	s.Require().Equal(http.StatusCreated, resp.StatusCode(), resp.Error())
	s.Require().Equal(email, resp.Result().(*gen.RegisterUserResponse).Username)

	tests := []struct {
		name       string
		body       gen.LoginUserRequest
		statusCode int
	}{
		{
			name: "normal",
			body: gen.LoginUserRequest{
				Password: password,
				Username: email,
			},
			statusCode: http.StatusOK,
		},
		{
			name: "wrong password",
			body: gen.LoginUserRequest{
				Password: "wrong_password",
				Username: email,
			},
			statusCode: http.StatusUnauthorized,
		},
		{
			name: "empty password",
			body: gen.LoginUserRequest{
				Password: "",
				Username: email,
			},
			statusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			resp, err := s.client.R().
				SetBody(tt.body).
				SetResult(&gen.LoginUserResponse{}).
				SetError(&gen.ErrorResponse{}).
				Post(s.httpAddress + "/login")

			s.Require().NoError(err)
			s.Require().Equal(tt.statusCode, resp.StatusCode(), resp.Error())

			if tt.statusCode >= 300 {
				return
			}
			res := resp.Result().(*gen.LoginUserResponse)

			_, err = s.jwtManager.VerifyToken(res.AccessToken)
			s.Require().NoError(err)
		})
	}
}
