package rp

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type fakeAuth struct{ asked []string }

func (f *fakeAuth) Begin(acr ...string) Request {
	f.asked = acr
	return Request{URL: "https://id.example/authorize?state=s1", State: "s1"}
}

func (f *fakeAuth) Finish(_ context.Context, req Request, answer url.Values) (Claims, error) {
	if answer.Get("state") != req.State {
		return Claims{}, ErrState
	}
	if answer.Get("who") == "weak" {
		return Claims{}, ErrWeak
	}
	return Claims{Subject: answer.Get("who"), Level: 2}, nil
}

func (f *fakeAuth) Access(_ context.Context, bearer string) (Claims, error) {
	if bearer == "tok-weak" {
		return Claims{Subject: "weak", Level: 2}, ErrWeak
	}
	if who, ok := strings.CutPrefix(bearer, "tok-"); ok {
		return Claims{Subject: who, Level: 3}, nil
	}
	return Claims{}, ErrToken
}

func (f *fakeAuth) Required() int { return 3 }

func TestWeb(t *testing.T) {
	auth := &fakeAuth{}
	w := NewWeb(auth, "svc", false, func(c Claims) (string, error) {
		if c.Subject == "mallory" {
			return "", ErrRefused
		}
		return c.Subject, nil
	})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", w.Login)
	mux.HandleFunc("GET /cb", w.Callback)
	mux.HandleFunc("POST /logout", w.Logout)
	mux.HandleFunc("GET /page", func(rw http.ResponseWriter, r *http.Request) {
		if id, ok := w.Page(rw, r); ok {
			io.WriteString(rw, id.User)
		}
	})
	mux.HandleFunc("GET /api", w.API(func(rw http.ResponseWriter, r *http.Request, id Identity) {
		Reply(rw, map[string]any{"user": id.User, "level": id.Claims.Level})
	}))
	srv := httptest.NewServer(SecureHeaders(mux))
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path string, header map[string]string) *http.Response {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		for k, v := range header {
			req.Header.Set(k, v)
		}
		r, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := get("/page", nil); r.StatusCode != http.StatusFound || r.Header.Get("Location") != "/login?back=%2Fpage" {
		t.Fatalf("a page opened without a session: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	if r := get("/cb?state=s1&who=alice", nil); r.StatusCode != http.StatusBadRequest {
		t.Fatal("a callback that did not start here was accepted")
	}
	get("/login?back=//evil.example/x", nil)
	if r := get("/cb?state=s1&who=alice", nil); r.Header.Get("Location") != "/" {
		t.Fatalf("an outside back address was followed: %s", r.Header.Get("Location"))
	}
	get("/login?back=/page&acr=sinty:3", nil)
	if len(auth.asked) != 1 || auth.asked[0] != "sinty:3" {
		t.Fatalf("the asked level was not passed on: %v", auth.asked)
	}
	if r := get("/cb?state=s1&who=alice", nil); r.Header.Get("Location") != "/page" {
		t.Fatalf("the sign-in did not return to the page: %s", r.Header.Get("Location"))
	}
	if r := get("/page", nil); r.StatusCode != 200 || r.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatal("the session did not open the page")
	}
	if r := get("/api", nil); r.StatusCode != http.StatusBadRequest {
		t.Fatal("a cookie request without the request header passed")
	}
	if r := get("/api", map[string]string{RequestHeader: "1"}); r.StatusCode != 200 {
		t.Fatal("the session did not reach the API")
	}
	if r := get("/api", map[string]string{"Authorization": "Bearer nope"}); r.StatusCode != http.StatusUnauthorized {
		t.Fatal("a bad bearer passed")
	}
	if r := get("/api", map[string]string{"Authorization": "Bearer tok-weak"}); r.StatusCode != http.StatusForbidden || !strings.Contains(r.Header.Get("WWW-Authenticate"), `insufficient_user_authentication", acr_values="sinty:3"`) {
		t.Fatalf("a weak bearer was not asked to step up: %d", r.StatusCode)
	}
	if r := get("/api", map[string]string{"Authorization": "Bearer tok-mallory"}); r.StatusCode != http.StatusUnauthorized {
		t.Fatal("a refused account passed with a bearer")
	}
	if r := get("/api", map[string]string{"Authorization": "Bearer tok-bob"}); r.StatusCode != 200 {
		t.Fatal("a good bearer was refused")
	}
	get("/login", nil)
	if r := get("/cb?state=s1&who=weak", nil); r.StatusCode != http.StatusForbidden {
		t.Fatal("a weak sign-in was not refused")
	}
	get("/login", nil)
	if r := get("/cb?state=s1&who=mallory", nil); r.StatusCode != http.StatusForbidden {
		t.Fatal("a refused account got a session")
	}
	req, _ := http.NewRequest("POST", srv.URL+"/logout", nil)
	req.Header.Set(RequestHeader, "1")
	c.Do(req)
	if r := get("/api", map[string]string{RequestHeader: "1"}); r.StatusCode != http.StatusUnauthorized {
		t.Fatal("the session survived logout")
	}
}
