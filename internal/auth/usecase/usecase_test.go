package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/Karzoug/innopolis-auth-go/internal/auth/entity"
	mock "github.com/Karzoug/innopolis-auth-go/internal/auth/mocks"
	"github.com/Karzoug/innopolis-auth-go/internal/auth/repository"
	"github.com/Karzoug/innopolis-auth-go/internal/buildinfo"
	"github.com/Karzoug/innopolis-auth-go/internal/gateway/http/gen"
	"github.com/Karzoug/innopolis-auth-go/internal/pkg/slogtest"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

const (
	email        = "alex@gmail.com"
	password     = "q12gt45*f"
	accessToken  = "acccess_token"
	refreshToken = "refresh_token"
)

type usecaseSuite struct {
	suite.Suite
	usecase AuthUseCase
}

func TestUsecaseSuite(t *testing.T) {
	suite.Run(t, new(usecaseSuite))
}

func (s *usecaseSuite) SetupSuite() {
	l := slogtest.NullLogger()

	ctrl := gomock.NewController(s.T())

	ur := mock.NewMockUserRepository(ctrl)
	ur.EXPECT().
		FindUserByEmail(gomock.Any(), gomock.Eq(email)).
		AnyTimes().
		Return(
			entity.UserAccount{
				Username:       email,
				HashedPassword: password,
				CreatedAt:      time.Now(),
			},
			nil,
		)
	ur.EXPECT().
		FindUserByEmail(gomock.Any(), gomock.Not(gomock.Eq(email))).
		AnyTimes().
		Return(entity.UserAccount{}, repository.ErrRecordNotFound)

	cp := mock.NewMockCryptoPassword(ctrl)
	cp.EXPECT().
		ComparePasswords(gomock.Any(), gomock.Any()).
		AnyTimes().
		DoAndReturn(func(fromUser, fromDB string) bool {
			return fromUser == fromDB
		})

	tr := mock.NewMockTokenRepository(ctrl)
	tr.EXPECT().
		Set(gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().
		Return()

	jm := mock.NewMockJWTManager(ctrl)
	jm.EXPECT().
		IssueAccessToken(gomock.Any()).
		AnyTimes().
		Return(accessToken, nil)
	jm.EXPECT().
		IssueRefreshToken(gomock.Any()).
		AnyTimes().
		Return(refreshToken, nil)
	jm.EXPECT().
		RefreshExpiresDuration().
		AnyTimes().
		Return(time.Hour)

	s.usecase = NewUseCase(ur, tr, cp, jm, buildinfo.New(), l)
}

func (s *usecaseSuite) TestPostLogin() {
	tests := []struct {
		name          string
		email         string
		password      string
		wantResponse  gen.PostLoginResponseObject
		needCheckResp bool
	}{
		{
			name:     "existing user",
			email:    email,
			password: password,
			wantResponse: gen.PostLogin200JSONResponse{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			needCheckResp: true,
		},
		{
			name:         "bad email format",
			email:        "email",
			password:     password,
			wantResponse: gen.PostLogin400JSONResponse{},
		},
		{
			name:         "not existing user",
			email:        "not_existing_email@gmail.com",
			password:     password,
			wantResponse: gen.PostLogin401JSONResponse{},
		},
		{
			name:         "wrong password",
			email:        email,
			password:     "wrong_password",
			wantResponse: gen.PostLogin401JSONResponse{},
		},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
			defer cancel()

			resp, err := s.usecase.PostLogin(ctx, gen.PostLoginRequestObject{
				Body: &gen.LoginUserRequest{
					Password: tt.password,
					Username: tt.email,
				},
			})

			s.Require().NoError(err)
			s.Require().IsType(tt.wantResponse, resp)

			if tt.needCheckResp {
				s.Require().Equal(tt.wantResponse, resp)
			}
		})
	}
}
