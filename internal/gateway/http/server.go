package http

import (
	"net/http"

	"github.com/Karzoug/innopolis-auth-go/config"
	"github.com/Karzoug/innopolis-auth-go/internal/auth/usecase"
	"github.com/Karzoug/innopolis-auth-go/internal/gateway/http/gen"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewAuthServer(cfg config.HTTPServer, uc usecase.AuthUseCase) http.Server {
	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)

	return http.Server{
		Addr:         cfg.Address,
		ReadTimeout:  cfg.Timeout,
		WriteTimeout: cfg.Timeout,
		Handler:      gen.HandlerFromMux(gen.NewStrictHandler(uc, nil), router),
	}
}
