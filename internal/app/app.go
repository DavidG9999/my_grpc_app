package app

import (
	"log/slog"
	"time"

	grpcapp "github.com/DavidG9999/my_grpc_app/internal/app/grpc"
	"github.com/DavidG9999/my_grpc_app/internal/services/auth"
	"github.com/DavidG9999/my_grpc_app/internal/storage"
	"github.com/DavidG9999/my_grpc_app/internal/storage/sqlite"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func NewApp(log *slog.Logger, grpcPort int, storagePath string, tokenTTL time.Duration) *App {

	db, err := sqlite.NewSQLiteDB(storagePath)
	if err != nil {
		
		panic(err)
	}

	storage := storage.NewStorage(db)

	authSrv := auth.NewAuth(log, storage, tokenTTL)

	grpcApp := grpcapp.NewApp(log, grpcPort, authSrv)

	return &App{
		GRPCSrv: grpcApp,
	}
}
