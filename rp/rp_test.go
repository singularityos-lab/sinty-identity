package rp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-identity/internal/provider"
	"github.com/singularityos-lab/sinty-identity/internal/secret"
	"github.com/singularityos-lab/sinty-identity/internal/store"
	"github.com/singularityos-lab/sinty-identity/rp"
)

func setup(t *testing.T) (*httptest.Server, string) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := secret.HashPassword("Corr3ct horse")
	seed := secret.NewTOTP()
	st.Update(func(s *store.State) error {
		s.Users["alice"] = &store.User{Name: "alice", Password: pw, TOTP: seed}
		s.Clients["cloud"] = &store.Client{ID: "cloud", Name: "Sinty Cloud", Redirects: []string{"https://cloud.example/cb"}, MinLevel: 1}
		s.Clients["cli"] = &store.Client{ID: "cli", Name: "Sinty command line", Redirects: []string{"http://127.0.0.1/cb"}, MinLevel: 1}
		return nil
	})
	srv := httptest.NewServer(nil)
	p, err := provider.New(srv.URL, st, "")
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = p.Handler()
	t.Cleanup(srv.Close)
	return srv, seed
}

func signIn(t *testing.T, srv *httptest.Server, start, otp string) url.Values {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(start)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	body, _ := json.Marshal(map[string]string{"flow": loc.Query().Get("flow"), "user": "alice", "password": "Corr3ct horse", "otp": otp})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/login/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sinty-Request", "1")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct{ Next string }
	json.NewDecoder(resp.Body).Decode(&out)
	next, err := url.Parse(out.Next)
	if err != nil || out.Next == "" {
		t.Fatalf("sign-in failed: %d", resp.StatusCode)
	}
	return next.Query()
}

func TestRelyingParty(t *testing.T) {
	srv, seed := setup(t)
	ctx := context.Background()
	if _, err := rp.New(ctx, rp.Config{Issuer: srv.URL + "/other", ClientID: "cloud"}); err == nil {
		t.Fatal("a provider at another address was trusted")
	}
	r, err := rp.New(ctx, rp.Config{Issuer: srv.URL, ClientID: "cloud", RedirectURL: "https://cloud.example/cb", MinLevel: 1})
	if err != nil {
		t.Fatal(err)
	}
	req := r.Begin()
	answer := signIn(t, srv, req.URL, "")
	forged := url.Values{"code": answer["code"], "state": {"other"}}
	if _, err := r.Finish(ctx, req, forged); !errors.Is(err, rp.ErrState) {
		t.Fatalf("an answer for another request was accepted: %v", err)
	}
	c, err := r.Finish(ctx, req, answer)
	if err != nil || c.Subject != "alice" || c.Level != 1 {
		t.Fatalf("finish: %v %+v", err, c)
	}
	if _, err := r.Finish(ctx, req, answer); err == nil {
		t.Fatal("the same answer was accepted twice")
	}

	strict, _ := rp.New(ctx, rp.Config{Issuer: srv.URL, ClientID: "cloud", RedirectURL: "https://cloud.example/cb", MinLevel: 2})
	req = strict.Begin()
	answer = signIn(t, srv, req.URL, "")
	if _, err := strict.Finish(ctx, req, answer); err == nil {
		t.Fatal("a password-only sign-in passed a service that needs two factors")
	}
	req = strict.Begin("sinty:2")
	code, _ := secret.TOTPAt(seed, time.Now())
	answer = signIn(t, srv, req.URL, code)
	c, err = strict.Finish(ctx, req, answer)
	if err != nil || c.Level != 2 {
		t.Fatalf("two-factor sign-in: %v %+v", err, c)
	}
}

func TestAccessTokens(t *testing.T) {
	srv, _ := setup(t)
	ctx := context.Background()
	r, _ := rp.New(ctx, rp.Config{Issuer: srv.URL, ClientID: "cloud", RedirectURL: "https://cloud.example/cb", MinLevel: 1})
	req := r.Begin()
	answer := signIn(t, srv, req.URL, "")
	form := url.Values{"grant_type": {"authorization_code"}, "code": answer["code"], "redirect_uri": {"https://cloud.example/cb"}, "code_verifier": {req.Verifier}, "client_id": {"cloud"}}
	resp, err := http.PostForm(srv.URL+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	var tokens map[string]string
	json.NewDecoder(resp.Body).Decode(&tokens)
	resp.Body.Close()
	if c, err := r.Access(ctx, tokens["access_token"]); err != nil || c.Subject != "alice" {
		t.Fatalf("access token refused: %v", err)
	}
	if _, err := r.Access(ctx, tokens["id_token"]); err == nil {
		t.Fatal("an ID token was accepted as an access token")
	}
	other, _ := rp.New(ctx, rp.Config{Issuer: srv.URL, ClientID: "it", RedirectURL: "https://it.example/cb", MinLevel: 1})
	if _, err := other.Access(ctx, tokens["access_token"]); err == nil {
		t.Fatal("a token for the cloud opened another service")
	}
	late, _ := rp.New(ctx, rp.Config{Issuer: srv.URL, ClientID: "cloud", Now: func() time.Time { return time.Now().Add(time.Hour) }})
	if _, err := late.Access(ctx, tokens["access_token"]); err == nil {
		t.Fatal("an expired token was accepted")
	}
}

func TestLoopback(t *testing.T) {
	srv, _ := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, tok, err := rp.LoopbackLogin(ctx, rp.Config{Issuer: srv.URL, ClientID: "cli", MinLevel: 1}, func(start string) error {
		go func() {
			answer := signIn(t, srv, start, "")
			back, _ := url.Parse(start)
			redirect := back.Query().Get("redirect_uri")
			resp, err := http.Get(redirect + "?" + answer.Encode())
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	})
	if err != nil || c.Subject != "alice" || tok.Access == "" {
		t.Fatalf("loopback sign-in: %v %+v", err, c)
	}
	cloud, _ := rp.New(ctx, rp.Config{Issuer: srv.URL, ClientID: "cloud", MinLevel: 1, Audiences: []string{"cli"}})
	if _, err := cloud.Access(ctx, tok.Access); err != nil {
		t.Fatalf("a service that trusts the command line refused its token: %v", err)
	}
	strict, _ := rp.New(ctx, rp.Config{Issuer: srv.URL, ClientID: "cloud", MinLevel: 1})
	if _, err := strict.Access(ctx, tok.Access); err == nil {
		t.Fatal("a token for another client was accepted without being allowed")
	}
}
