package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nadamu/dyatel/internal/api"
	"nadamu/dyatel/internal/config"
	"nadamu/dyatel/internal/reconcile"
	"nadamu/dyatel/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	st, err := store.Open(ctx, cfg.DatabaseDSN)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Pool.Close()

	rc := reconcile.New(cfg, st)
	go rc.Run(ctx)

	srv := &http.Server{
		Addr:              cfg.Bind,
		Handler:           api.New(cfg, st, rc).Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, c2 := context.WithTimeout(context.Background(), 10*time.Second)
		defer c2()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Printf("dyatel-core listening on %s", cfg.Bind)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}