package commands

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Karzoug/innopolis-auth-go/config"
	"github.com/Karzoug/innopolis-auth-go/internal/auth/repository"
	"github.com/Karzoug/innopolis-auth-go/internal/auth/usecase"
	"github.com/Karzoug/innopolis-auth-go/internal/buildinfo"
	gwHttp "github.com/Karzoug/innopolis-auth-go/internal/gateway/http"
	"github.com/Karzoug/innopolis-auth-go/internal/pkg/crypto"
	"github.com/Karzoug/innopolis-auth-go/internal/pkg/jwt"
	"github.com/spf13/cobra"
)

func NewServeCmd() *cobra.Command {
	var configPath string

	c := &cobra.Command{
		Use:     "serve",
		Aliases: []string{"s"},
		Short:   "Start API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
			defer cancel()

			cfg, err := config.Parse(configPath)
			if err != nil {
				return err
			}
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
			logger.Info("successfully loaded config")

			ctxStorage, cancel := context.WithTimeout(ctx, time.Second*3)
			defer cancel()
			storage, err := repository.New(ctxStorage, cfg.Storage.SQLitePath)
			if err != nil {
				return err
			}

			passwordHasher := crypto.NewPasswordHasher()
			jwtManager, err := jwt.NewJWTManager(jwt.Config{
				Issuer:           cfg.JWT.Issuer,
				AccessExpiresIn:  cfg.JWT.AccessExpiresIn,
				RefreshExpiresIn: cfg.JWT.RefreshExpiresIn,
				PublicKey:        []byte(cfg.JWT.PublicKey),
				PrivateKey:       []byte(cfg.JWT.PrivateKey),
			})
			if err != nil {
				return err
			}

			tr := repository.NewRWMap[string, string](cfg.TokenStorage.CleaningInterval)
			useCase := usecase.NewUseCase(&storage,
				tr,
				passwordHasher,
				jwtManager,
				buildinfo.New(),
				logger)

			httpServer := gwHttp.NewAuthServer(cfg.HTTPServer, useCase)

			go func() {
				if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
					logger.Error("ListenAndServe", slog.Any("err", err))
				}
			}()
			logger.Info("server listening:", slog.String("port", cfg.HTTPServer.Address))
			<-ctx.Done()

			closeCtx, _ := context.WithTimeout(context.Background(), time.Second*5)
			if err := httpServer.Shutdown(closeCtx); err != nil {
				logger.Error("httpServer.Shutdown", slog.String("error", err.Error()))
			}

			if err := storage.Close(); err != nil {
				logger.Error("storage.Close", slog.String("error", err.Error()))
			}

			return nil
		},
	}
	c.Flags().StringVar(&configPath, "config", "config.yaml", "path to config")
	return c
}
