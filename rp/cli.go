package rp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrSignedOut = errors.New("not signed in")
	ErrNotFound  = errors.New("not found")
)

type APIError struct {
	Status int
	Code   string
	Body   map[string]any
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("the server answered %d", e.Status)
	}
	return e.Code
}

type Session struct {
	Server  string       `json:"server"`
	Token   string       `json:"token"`
	Expires time.Time    `json:"expires"`
	HTTP    *http.Client `json:"-"`
}

func sessionPath(app string) (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, app, "credentials.json"), nil
}

func SaveSession(app string, s Session) error {
	path, err := sessionPath(app)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func LoadSession(app string) (Session, error) {
	var s Session
	path, err := sessionPath(app)
	if err != nil {
		return s, err
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &s) != nil || s.Token == "" || time.Now().After(s.Expires) {
		return Session{}, ErrSignedOut
	}
	return s, nil
}

func ForgetSession(app string) error {
	path, err := sessionPath(app)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func OpenBrowser(u string) error {
	fmt.Fprintln(os.Stderr, "Sign in at:", u)
	if opener := os.Getenv("SINTY_BROWSER"); opener != "" {
		return exec.Command(opener, u).Start()
	}
	exec.Command("xdg-open", u).Start()
	return nil
}

func CommandLineLogin(ctx context.Context, app, server string, cfg Config, acr ...string) (Claims, Session, error) {
	claims, tok, err := LoopbackLogin(ctx, cfg, OpenBrowser, acr...)
	if err != nil {
		return Claims{}, Session{}, err
	}
	s := Session{Server: strings.TrimRight(server, "/"), Token: tok.Access, Expires: tok.Expires}
	return claims, s, SaveSession(app, s)
}

func (s Session) Do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.Server+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c := s.HTTP
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 == 2 {
		return resp, nil
	}
	defer resp.Body.Close()
	var payload map[string]any
	json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&payload)
	code, _ := payload["error"].(string)
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, ErrSignedOut
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	}
	return nil, &APIError{Status: resp.StatusCode, Code: code, Body: payload}
}

func (s Session) JSON(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(raw))
	}
	resp, err := s.Do(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
