package rp

import (
	"context"
	"errors"
	"net/http"
	"time"
)

func Connect(ctx context.Context, cfg Config, logf func(string, ...any)) (*RP, error) {
	for {
		r, err := New(ctx, cfg)
		if err == nil || ctx.Err() != nil {
			return r, err
		}
		logf("waiting for the identity provider: %v", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func Serve(ctx context.Context, addr string, h http.Handler, cert, key string) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shut)
	}()
	var err error
	if cert != "" {
		err = srv.ListenAndServeTLS(cert, key)
	} else {
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
