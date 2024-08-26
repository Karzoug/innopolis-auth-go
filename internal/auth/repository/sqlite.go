package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Karzoug/innopolis-auth-go/internal/auth/entity"
	"github.com/mattn/go-sqlite3"
	_ "github.com/mattn/go-sqlite3"
)

type SQLLiteStorage struct {
	db *sql.DB
}

func New(ctx context.Context, dbPath string) (SQLLiteStorage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return SQLLiteStorage{}, err
	}
	_, err = db.ExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY,
		username text not null unique,
		password text not null,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
	create index if not exists idx_username ON users(username);
	`, nil)
	if err != nil {
		return SQLLiteStorage{}, fmt.Errorf("db schema init err: %w", err)
	}

	return SQLLiteStorage{db: db}, nil
}

func (s *SQLLiteStorage) Close() error {
	return s.db.Close()
}

func (s *SQLLiteStorage) RegisterUser(ctx context.Context, u entity.UserAccount) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users(username, password) VALUES(?,?)`,
		u.Username, u.Password)
	if errors.Is(err, sqlite3.ErrConstraintUnique) {
		return ErrAlreadyExists
	}
	return err
}

func (s *SQLLiteStorage) FindUserByEmail(ctx context.Context, username string) (entity.UserAccount, error) {
	var pswdFromDB string
	if err := s.db.QueryRowContext(ctx,
		`SELECT password FROM users WHERE username = ?`,
		username).
		Scan(&pswdFromDB); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return entity.UserAccount{}, ErrRecordNotFound
		}
		return entity.UserAccount{}, err
	}

	return entity.UserAccount{
		Username: username,
		Password: pswdFromDB,
	}, nil
}
