package provider

import (
	_ "embed"
	"html/template"
	"net/http"
)

//go:embed login.html
var loginHTML string

//go:embed login.js
var loginJS []byte

var loginTemplate = template.Must(template.New("login").Parse(loginHTML))

func (p *Provider) loginPage(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("flow")
	f := p.takeFlow(id)
	if f == nil {
		http.Error(w, "This sign-in request has expired. Go back to the application and try again.", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	loginTemplate.Execute(w, map[string]any{"Flow": id, "Client": f.client.Name, "Issuer": p.Issuer, "PasswordAllowed": f.minLevel <= 2})
}

func (p *Provider) loginScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Write(loginJS)
}
