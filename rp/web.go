package rp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const RequestHeader = "X-Sinty-Request"

type Authenticator interface {
	Begin(acr ...string) Request
	Finish(ctx context.Context, req Request, answer url.Values) (Claims, error)
	Access(ctx context.Context, bearer string) (Claims, error)
}

type Identity struct {
	User   string
	Claims Claims
}

type Web struct {
	Auth       Authenticator
	Cookie     string
	Secure     bool
	Home       string
	SessionTTL time.Duration
	Accept     func(Claims) (string, error)
	Now        func() time.Time

	mu       sync.Mutex
	sessions map[string]webSession
	logins   map[string]webLogin
}

type webSession struct {
	id      Identity
	expires time.Time
}

type webLogin struct {
	req     Request
	back    string
	expires time.Time
}

const loginTTL = 10 * time.Minute

var ErrRefused = errors.New("rp: this account cannot use the service")

func NewWeb(auth Authenticator, cookie string, secure bool, accept func(Claims) (string, error)) *Web {
	return &Web{Auth: auth, Cookie: cookie, Secure: secure, Home: "/", SessionTTL: 8 * time.Hour, Accept: accept, Now: time.Now,
		sessions: map[string]webSession{}, logins: map[string]webLogin{}}
}

func (w *Web) set(rw http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(rw, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: w.Secure, SameSite: http.SameSiteLaxMode, MaxAge: int(ttl / time.Second)})
}

func (w *Web) gc() {
	now := w.Now()
	for k, v := range w.sessions {
		if now.After(v.expires) {
			delete(w.sessions, k)
		}
	}
	for k, v := range w.logins {
		if now.After(v.expires) {
			delete(w.logins, k)
		}
	}
}

func localPath(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") {
		return ""
	}
	return p
}

func (w *Web) Login(rw http.ResponseWriter, r *http.Request) {
	var acr []string
	if a := r.URL.Query().Get("acr"); a != "" {
		acr = []string{a}
	}
	back := localPath(r.URL.Query().Get("back"))
	if back == "" {
		back = w.Home
	}
	req := w.Auth.Begin(acr...)
	w.mu.Lock()
	w.gc()
	w.logins[req.State] = webLogin{req: req, back: back, expires: w.Now().Add(loginTTL)}
	w.mu.Unlock()
	w.set(rw, w.Cookie+"_login", req.State, loginTTL)
	http.Redirect(rw, r, req.URL, http.StatusFound)
}

func (w *Web) Callback(rw http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(w.Cookie + "_login")
	if err != nil {
		http.Error(rw, "This sign-in did not start here.", http.StatusBadRequest)
		return
	}
	w.mu.Lock()
	p, ok := w.logins[c.Value]
	delete(w.logins, c.Value)
	w.mu.Unlock()
	w.set(rw, w.Cookie+"_login", "", -time.Second)
	if !ok || w.Now().After(p.expires) {
		http.Error(rw, "This sign-in has expired.", http.StatusBadRequest)
		return
	}
	claims, err := w.Auth.Finish(r.Context(), p.req, r.URL.Query())
	if errors.Is(err, ErrWeak) {
		http.Error(rw, "This needs a stronger sign-in.", http.StatusForbidden)
		return
	}
	if err != nil {
		http.Error(rw, "The sign-in was refused.", http.StatusUnauthorized)
		return
	}
	user, err := w.Accept(claims)
	if err != nil {
		http.Error(rw, "This account cannot use this service.", http.StatusForbidden)
		return
	}
	id := token(32)
	w.mu.Lock()
	if old, err := r.Cookie(w.Cookie); err == nil {
		delete(w.sessions, old.Value)
	}
	w.sessions[id] = webSession{id: Identity{User: user, Claims: claims}, expires: w.Now().Add(w.SessionTTL)}
	w.mu.Unlock()
	w.set(rw, w.Cookie, id, w.SessionTTL)
	http.Redirect(rw, r, p.back, http.StatusFound)
}

func (w *Web) Logout(rw http.ResponseWriter, r *http.Request) {
	if r.Header.Get(RequestHeader) == "" {
		http.Error(rw, "missing request header", http.StatusBadRequest)
		return
	}
	if c, err := r.Cookie(w.Cookie); err == nil {
		w.mu.Lock()
		delete(w.sessions, c.Value)
		w.mu.Unlock()
	}
	w.set(rw, w.Cookie, "", -time.Second)
	rw.WriteHeader(http.StatusNoContent)
}

func (w *Web) Session(r *http.Request) (Identity, bool) {
	c, err := r.Cookie(w.Cookie)
	if err != nil {
		return Identity{}, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	v, ok := w.sessions[c.Value]
	if !ok || w.Now().After(v.expires) {
		return Identity{}, false
	}
	return v.id, true
}

func (w *Web) Page(rw http.ResponseWriter, r *http.Request) (Identity, bool) {
	id, ok := w.Session(r)
	if !ok {
		http.Redirect(rw, r, "/login?back="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
	}
	return id, ok
}

func (w *Web) API(h func(rw http.ResponseWriter, r *http.Request, id Identity)) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Cache-Control", "no-store")
		if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			claims, err := w.Auth.Access(r.Context(), bearer)
			user := ""
			if err == nil {
				user, err = w.Accept(claims)
			}
			if err != nil {
				rw.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				Fail(rw, http.StatusUnauthorized, "invalid_token")
				return
			}
			h(rw, r, Identity{User: user, Claims: claims})
			return
		}
		if r.Header.Get(RequestHeader) == "" {
			Fail(rw, http.StatusBadRequest, "missing_request_header")
			return
		}
		id, ok := w.Session(r)
		if !ok {
			Fail(rw, http.StatusUnauthorized, "sign_in")
			return
		}
		h(rw, r, id)
	}
}

func Fail(rw http.ResponseWriter, status int, code string) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	json.NewEncoder(rw).Encode(map[string]string{"error": code})
}

func Reply(rw http.ResponseWriter, v any) {
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(v)
}

func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.Header().Set("Referrer-Policy", "no-referrer")
		rw.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(rw, r)
	})
}
