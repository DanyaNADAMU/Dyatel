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

	// The data plane starts first: a node must keep (or restore) its tunnels
	// even when the control-plane database is unreachable. The pool connects
	// lazily, migration retries in the background, and the reconcile loop
	// falls back to the configs on disk while the database is away.
	st, err := store.Open(ctx, cfg.DatabaseDSN)
	if err != nil {
		log.Fatalf("db pool: %v", err)
	}
	defer st.Pool.Close()

	rc := reconcile.New(cfg, st)
	go rc.Run(ctx)
	go func() {
		for {
			mctx, mcancel := context.WithTimeout(ctx, 15*time.Second)
			err := st.MigrateUp(mctx)
			mcancel()
			if err == nil {
				log.Printf("dyatel-core: database ready")
				return
			}
			log.Printf("dyatel-core: database unavailable (%v); serving tunnels from disk", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
	}()

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
