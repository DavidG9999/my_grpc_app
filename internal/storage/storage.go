package storage

import (
	"context"
	"database/sql"
	"errors"

	"github.com/DavidG9999/my_grpc_app/internal/domain/models"
)

var (
	ErrUserExists   = errors.New("user already exist")
	ErrUserNotFound = errors.New("user not found")
	ErrAppNotFound  = errors.New("app nor found")
)

type Auth interface {
	SaveUser(ctx context.Context, name string, email string, passwordHash []byte, isAdmin bool) (int64, error)
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
	App(ctx context.Context, appID int) (models.App, error)
}

type Storage struct {
	Auth
}

func NewStorage(db *sql.DB) *Storage {
	return &Storage{
		Auth: NewAuthStorage(db),
	}
}
