package rp

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"time"
)

func LoopbackLogin(ctx context.Context, cfg Config, show func(string) error, acr ...string) (Claims, Tokens, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Claims{}, Tokens{}, err
	}
	defer ln.Close()
	cfg.RedirectURL = fmt.Sprintf("http://%s/cb", ln.Addr())
	r, err := New(ctx, cfg)
	if err != nil {
		return Claims{}, Tokens{}, err
	}
	req := r.Begin(acr...)
	answers := make(chan url.Values, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, hr *http.Request) {
		if hr.URL.Path != "/cb" || hr.URL.Query().Get("state") != req.State {
			http.NotFound(w, hr)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><title>Signed in</title><p>%s</p>", html.EscapeString("You can close this window and go back to the terminal."))
		select {
		case answers <- hr.URL.Query():
		default:
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()
	if err := show(req.URL); err != nil {
		return Claims{}, Tokens{}, err
	}
	select {
	case <-ctx.Done():
		return Claims{}, Tokens{}, errors.Join(ErrState, ctx.Err())
	case answer := <-answers:
		return r.Exchange(ctx, req, answer)
	}
}
