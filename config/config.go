package config

import (
	"log/slog"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	LogLevel     slog.Level   `yaml:"log_level" env-default:"INFO"`
	HTTPServer   HTTPServer   `yaml:"http_server"`
	Storage      Storage      `yaml:"storage"`
	TokenStorage TokenStorage `yaml:"token_storage"`
	JWT          JWT          `yaml:"jwt"`
}

type HTTPServer struct {
	Address string        `yaml:"address" env-default:":8080"`
	Timeout time.Duration `yaml:"timeout" env-default:"5s"`
}

type Storage struct {
	SQLitePath string `yaml:"path" env-default:"app.db"`
}

type TokenStorage struct {
	CleaningInterval time.Duration `yaml:"cleaning_interval" env-default:"10m"`
}

type JWT struct {
	Issuer           string        `yaml:"issuer"`
	AccessExpiresIn  time.Duration `yaml:"access_expires_in"`
	RefreshExpiresIn time.Duration `yaml:"refresh_expires_in"`
	PublicKey        string        `yaml:"public_key"`
	PrivateKey       string        `yaml:"private_key"`
}

func Parse(s string) (*Config, error) {
	c := &Config{}
	if err := cleanenv.ReadConfig(s, c); err != nil {
		return nil, err
	}

	privateKey, err := os.ReadFile(c.JWT.PrivateKey)
	if err != nil {
		return nil, err
	}
	publicKey, err := os.ReadFile(c.JWT.PublicKey)
	if err != nil {
		return nil, err
	}
	c.JWT.PrivateKey = string(privateKey)
	c.JWT.PublicKey = string(publicKey)

	return c, nil
}
