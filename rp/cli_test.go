package rp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionFile(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if _, err := LoadSession("app"); !errors.Is(err, ErrSignedOut) {
		t.Fatal("a session appeared from nothing")
	}
	SaveSession("app", Session{Server: "https://x", Token: "t", Expires: time.Now().Add(-time.Minute)})
	if _, err := LoadSession("app"); !errors.Is(err, ErrSignedOut) {
		t.Fatal("an expired session was used")
	}
	SaveSession("app", Session{Server: "https://x", Token: "t", Expires: time.Now().Add(time.Hour)})
	info, err := os.Stat(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "app", "credentials.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("credentials file mode: %v %v", info.Mode(), err)
	}
	if s, err := LoadSession("app"); err != nil || s.Token != "t" {
		t.Fatal(err)
	}
	ForgetSession("app")
	if _, err := LoadSession("app"); !errors.Is(err, ErrSignedOut) {
		t.Fatal("a forgotten session was used")
	}
}

func TestSessionDo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good" {
			Fail(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		switch r.URL.Path {
		case "/ok":
			Reply(w, map[string]string{"hello": "world"})
		case "/gone":
			Fail(w, http.StatusNotFound, "not_found")
		default:
			Fail(w, http.StatusForbidden, "second_admin")
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	s := Session{Server: srv.URL, Token: "good"}
	var out map[string]string
	if err := s.JSON(ctx, "GET", "/ok", nil, &out); err != nil || out["hello"] != "world" {
		t.Fatal(err)
	}
	if err := s.JSON(ctx, "GET", "/gone", nil, nil); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	var api *APIError
	if err := s.JSON(ctx, "POST", "/x", map[string]int{"a": 1}, nil); !errors.As(err, &api) || api.Code != "second_admin" || api.Status != 403 {
		t.Fatal(err)
	}
	s.Token = "bad"
	if err := s.JSON(ctx, "GET", "/ok", nil, nil); !errors.Is(err, ErrSignedOut) {
		t.Fatal(err)
	}
}
