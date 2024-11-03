package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/DavidG9999/my_grpc_app/internal/domain/models"
	"github.com/DavidG9999/my_grpc_app/internal/lib/jwt"
	"github.com/DavidG9999/my_grpc_app/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	log      *slog.Logger
	authSrv  AuthService
	tokenTTL time.Duration
}

type UserSaver interface {
	SaveUser(ctx context.Context, name string, email string, passwordHash []byte, isAdmin bool) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

type AuthService interface {
	UserSaver
	UserProvider
	AppProvider
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidAppID       = errors.New("invalid app ID")
	ErrUserExist          = errors.New("user already exist")
	ErrUserNotFound       = errors.New("user not found")
)

func NewAuth(log *slog.Logger, authSrv AuthService, tokenTTL time.Duration) *Auth {
	return &Auth{
		log:      log,
		authSrv:  authSrv,
		tokenTTL: tokenTTL,
	}
}

func (a *Auth) SignIn(ctx context.Context, email string, password string, appId int) (string, error) {
	const op = "auth.SignIn"

	log := a.log.With(
		slog.String("op", op),
	)

	log.Info("logining user")

	user, err := a.authSrv.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found")

			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}
		a.log.Error("failed to get user")

		return "", fmt.Errorf("%s: %w", op, err)
	}
	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials")

		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}
	app, err := a.authSrv.App(ctx, appId)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			a.log.Warn("app not found")

			return "", fmt.Errorf("%s: %w", op, ErrInvalidAppID)
		}
		a.log.Error("failed to get app")

		return "", fmt.Errorf("%s: %w", op, err)
	}
	log.Info("user logged in sucessfully")

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token")

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (a *Auth) SighUp(ctx context.Context, name string, email string, password string, isAdmin bool) (id int64, err error) {
	const op = "auth.SignUp"

	log := a.log.With(
		slog.String("op", op),
	)
	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash")
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	id, err = a.authSrv.SaveUser(ctx, name, email, passHash, isAdmin)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			a.log.Warn("user already exist")

			return 0, fmt.Errorf("%s: %w", op, ErrUserExist)
		}
		log.Error("failed to save user")

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user registered")
	return id, nil
}

func (a *Auth) IsAdmin(ctx context.Context, userId int64) (isAdmin bool, err error) {
	const op = "auth.IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userId),
	)
	log.Info("cheking if user is admin")

	isAdmin, err = a.authSrv.IsAdmin(ctx, userId)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found")

			return false, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("checked if user is admin", slog.Bool("is_admin", isAdmin))
	return isAdmin, nil
}
