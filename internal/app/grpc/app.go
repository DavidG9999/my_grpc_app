package grpcapp

import (
	"fmt"
	"log/slog"
	"net"

	authgrpc "github.com/DavidG9999/my_grpc_app/internal/grpc/auth"
	"github.com/DavidG9999/my_grpc_app/internal/services/auth"
	"google.golang.org/grpc"
)

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       int
}

func NewApp(log *slog.Logger, port int, authService *auth.Auth) *App {
	gRPCServer := grpc.NewServer()

	authgrpc.Register(gRPCServer, *authService)

	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	const op = "gprcapp.Run"

	log := a.log.With(slog.String("op", op), slog.Int("port", a.port))

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("grpc server is running", slog.String("addr", l.Addr().String()))

	if err := a.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *App) Stop() {
	const op = "gprcapp.Stop"

	log := a.log.With(slog.String("op", op))

	a.gRPCServer.GracefulStop()

	log.Info("stopping gRPC server")

}
