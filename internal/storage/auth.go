package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/DavidG9999/my_grpc_app/internal/domain/models"
	"github.com/mattn/go-sqlite3"
)

type AuthStorage struct {
	db *sql.DB
}

func NewAuthStorage(db *sql.DB) *AuthStorage {
	return &AuthStorage{db: db}
}

func (s *AuthStorage) SaveUser(ctx context.Context, name string, email string, passwordHash []byte, isAdmin bool) (int64, error) {
	const op = "storage.sqlite.SaveUser"

	stmp, err := s.db.Prepare("INSERT INTO users(name, email, password_hash, is_admin) VALUES(?, ?, ?, ?)")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	res, err := stmp.ExecContext(ctx, name, email, passwordHash, isAdmin)
	if err != nil {
		var sqliteErr sqlite3.Error

		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return 0, fmt.Errorf("%s: %w", op, ErrUserExists)

		}
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	return id, nil
}

func (s *AuthStorage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.sqlite.User"

	stmp, err := s.db.Prepare("SELECT id, name, email, password_hash FROM users WHERE email=?")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	row := stmp.QueryRowContext(ctx, email)

	var user models.User
	err = row.Scan(&user.ID, &user.Name, &user.Email, &user.PasswordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	return user, nil
}

func (s *AuthStorage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "storage.sqlite.IsAdmin"

	stmp, err := s.db.Prepare("SELECT is_admin FROM users WHERE id=?")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	row := stmp.QueryRowContext(ctx, userID)

	var isAdmin bool
	err = row.Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return isAdmin, nil
}

func (s *AuthStorage) App(ctx context.Context, appID int) (models.App, error) {
	const op = "storage.sqlite.App"

	stmp, err := s.db.Prepare("SELECT * FROM apps WHERE id=?")
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmp.QueryRowContext(ctx, appID)

	var app models.App
	err = row.Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, fmt.Errorf("%s: %w", op, ErrAppNotFound)
		}
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	return app, nil
}
