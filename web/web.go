package web

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	"github.com/dlukt/pdns-manager/auth"
	"github.com/dlukt/pdns-manager/config"
	"github.com/dlukt/pdns-manager/ent"
	"github.com/dlukt/pdns-manager/ent/settings"
	"github.com/dlukt/pdns-manager/pdns"
	"github.com/dlukt/pdns-manager/session"
)

//go:embed templates/*.html templates/auth/*.html templates/settings/*.html templates/zones/*.html static/*
var contentFS embed.FS

var (
	tmpl     = mustTemplates()
	staticFS = mustStatic()
)

func mustStatic() fs.FS {
	s, err := fs.Sub(contentFS, "static")
	if err != nil {
		panic(err)
	}
	return s
}

func mustTemplates() map[string]*template.Template {
	base, err := template.ParseFS(contentFS, "templates/base.html", "templates/layout.html")
	if err != nil {
		panic(err)
	}

	tmpls := make(map[string]*template.Template)
	err = fs.WalkDir(contentFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".html") {
			return nil
		}
		name := strings.TrimPrefix(path, "templates/")
		switch {
		case name == "base.html" || name == "layout.html":
			return nil
		case strings.HasPrefix(name, "auth/"):
			b, err := contentFS.ReadFile(path)
			if err != nil {
				return err
			}
			tmpls[name] = template.Must(template.New(name).Parse(string(b)))
			return nil
		default:
			b, err := contentFS.ReadFile(path)
			if err != nil {
				return err
			}
			cl, err := base.Clone()
			if err != nil {
				return err
			}
			if _, err := cl.Parse(string(b)); err != nil {
				return err
			}
			tmpls[name] = cl.Lookup(name)
			return nil
		}
	})
	if err != nil {
		panic(err)
	}
	return tmpls
}

type handler struct {
	auth       *auth.Service
	sessions   *session.Store
	client     *ent.Client
	pdnsClient pdnsClient
	zoneKinds  []string
}

type pdnsClient interface {
	ListServers(ctx context.Context) ([]pdns.Server, error)
	CreateZone(ctx context.Context, serverID string, zone pdns.Zone) (*pdns.Zone, error)
	DeleteZone(ctx context.Context, serverID, zoneID string) error
}

// NewHandler returns an http.Handler with application routes.
func NewHandler(c *ent.Client, a *auth.Service, s *session.Store, p pdnsClient) http.Handler {
	h := &handler{
		auth:       a,
		sessions:   s,
		client:     c,
		pdnsClient: p,
		zoneKinds:  []string{"Native", "Master", "Slave"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", h.index)
	mux.HandleFunc("GET /auth/register", h.getRegister)
	mux.HandleFunc("POST /auth/register", h.postRegister)
	mux.HandleFunc("GET /auth/login", h.getLogin)
	mux.HandleFunc("POST /auth/login", h.postLogin)
	mux.HandleFunc("GET /auth/logout", h.getLogout)
	mux.HandleFunc("GET /auth/reset", h.getReset)
	mux.HandleFunc("POST /auth/reset", h.postReset)
	mux.HandleFunc("GET /auth/forgot", h.getForgot)
	mux.HandleFunc("POST /auth/forgot", h.postForgot)
	mux.HandleFunc("GET /auth/confirm_mail", h.confirmMail)
	mux.HandleFunc("GET /settings/server", h.getServerSettings)
	mux.HandleFunc("POST /settings/server", h.postServerSettings)
	mux.HandleFunc("GET /zones/new", h.getZoneNew)
	mux.HandleFunc("POST /zones", h.postZoneCreate)
	mux.HandleFunc("POST /zones/{serverID}/{zoneID}/delete", h.postZoneDelete)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	return h.loginRequired(mux)
}

func (h *handler) loginRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/auth/") || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie("session")
		if err != nil {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		if _, ok := h.sessions.Get(c.Value); !ok {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	data := struct{ Title string }{Title: "PDNS Manager"}
	if err := tmpl["index.html"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type zoneForm struct {
	ServerID string
	Name     string
	Kind     string
	Masters  string
}

type zonePageData struct {
	Title       string
	Error       string
	FieldErrors map[string]string
	Form        zoneForm
	Servers     []pdns.Server
	Kinds       []string
}

func (h *handler) getZoneNew(w http.ResponseWriter, r *http.Request) {
	data := zonePageData{
		Title:       "Create Zone",
		FieldErrors: map[string]string{},
		Form: zoneForm{
			Kind: h.zoneKinds[0],
		},
		Kinds: h.zoneKinds,
	}
	servers, err := h.listServers(r)
	if err != nil {
		data.Error = err.Error()
	} else {
		data.Servers = servers
	}
	h.renderZoneForm(w, data)
}

func (h *handler) postZoneCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	form := zoneForm{
		ServerID: strings.TrimSpace(r.FormValue("server_id")),
		Name:     strings.TrimSpace(r.FormValue("name")),
		Kind:     strings.TrimSpace(r.FormValue("kind")),
		Masters:  strings.TrimSpace(r.FormValue("masters")),
	}
	if form.Kind == "" {
		form.Kind = h.zoneKinds[0]
	}
	data := zonePageData{
		Title:       "Create Zone",
		FieldErrors: map[string]string{},
		Form:        form,
		Kinds:       h.zoneKinds,
	}
	servers, err := h.listServers(r)
	if err != nil {
		data.Error = err.Error()
		h.renderZoneForm(w, data)
		return
	}
	data.Servers = servers
	if form.ServerID == "" {
		data.FieldErrors["server_id"] = "Please select a server."
	} else if !h.serverExists(servers, form.ServerID) {
		data.FieldErrors["server_id"] = "Selected server is not available."
	}
	if form.Name == "" {
		data.FieldErrors["name"] = "Zone name is required."
	}
	normalizedKind, kindErr := h.normalizeKind(form.Kind)
	if kindErr != "" {
		data.FieldErrors["kind"] = kindErr
	} else {
		data.Form.Kind = normalizedKind
	}
	masters := parseMasters(form.Masters)
	if kindErr == "" && normalizedKind == "Slave" && len(masters) == 0 {
		data.FieldErrors["masters"] = "At least one master is required for slave zones."
	}
	if len(data.FieldErrors) > 0 {
		h.renderZoneForm(w, data)
		return
	}
	zone := pdns.Zone{
		Name: form.Name,
		Kind: data.Form.Kind,
	}
	if len(masters) > 0 {
		zone.Masters = masters
	}
	if _, err := h.pdnsClient.CreateZone(r.Context(), form.ServerID, zone); err != nil {
		data.Error = err.Error()
		h.renderZoneForm(w, data)
		return
	}
	msg := fmt.Sprintf("Zone %s created successfully.", form.Name)
	http.Redirect(w, r, "/zones?success="+url.QueryEscape(msg), http.StatusFound)
}

func (h *handler) postZoneDelete(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	if _, ok := h.sessions.Get(c.Value); !ok {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	serverID := r.PathValue("serverID")
	zoneID := r.PathValue("zoneID")
	if serverID == "" || zoneID == "" {
		http.Error(w, "missing identifiers", http.StatusBadRequest)
		return
	}
	if h.pdnsClient == nil {
		http.Redirect(w, r, "/zones?error="+url.QueryEscape("PowerDNS client is not configured"), http.StatusFound)
		return
	}
	if err := h.pdnsClient.DeleteZone(r.Context(), serverID, zoneID); err != nil {
		http.Redirect(w, r, "/zones?error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	msg := fmt.Sprintf("Zone %s deleted successfully.", zoneID)
	http.Redirect(w, r, "/zones?success="+url.QueryEscape(msg), http.StatusFound)
}

func (h *handler) renderZoneForm(w http.ResponseWriter, data zonePageData) {
	if err := tmpl["zones/new.html"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) listServers(r *http.Request) ([]pdns.Server, error) {
	if h.pdnsClient == nil {
		return nil, fmt.Errorf("PowerDNS client is not configured")
	}
	servers, err := h.pdnsClient.ListServers(r.Context())
	if err != nil {
		return nil, fmt.Errorf("failed to load servers: %w", err)
	}
	return servers, nil
}

func (h *handler) serverExists(servers []pdns.Server, id string) bool {
	for _, s := range servers {
		if s.ID == id {
			return true
		}
	}
	return false
}

func (h *handler) normalizeKind(kind string) (string, string) {
	switch strings.ToLower(kind) {
	case "native":
		return "Native", ""
	case "master":
		return "Master", ""
	case "slave":
		return "Slave", ""
	default:
		return kind, "Invalid zone kind."
	}
}

func parseMasters(input string) []string {
	if input == "" {
		return nil
	}
	fields := strings.FieldsFunc(input, func(r rune) bool {
		switch r {
		case ',', ';', '\n', '\r':
			return true
		default:
			return false
		}
	})
	masters := make([]string, 0, len(fields))
	for _, f := range fields {
		v := strings.TrimSpace(f)
		if v != "" {
			masters = append(masters, v)
		}
	}
	return masters
}

func (h *handler) getRegister(w http.ResponseWriter, r *http.Request) {
	data := struct{ Title, Error, Message string }{Title: "Register"}
	if err := tmpl["auth/register.html"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) postRegister(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	in := auth.RegisterInput{
		FirstName: r.FormValue("first_name"),
		LastName:  r.FormValue("last_name"),
		Email:     r.FormValue("email"),
		Password:  r.FormValue("password"),
	}
	_, _, err := h.auth.Register(r.Context(), in)
	data := struct{ Title, Error, Message string }{Title: "Register"}
	if err != nil {
		data.Error = err.Error()
	} else {
		data.Message = "Registration successful. Please check your email for a verification link."
	}
	if err := tmpl["auth/register.html"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) getLogin(w http.ResponseWriter, r *http.Request) {
	data := struct{ Title, Error, Message string }{Title: "Login"}
	if err := tmpl["auth/login.html"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) postLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := h.auth.Login(r.Context(), r.FormValue("email"), r.FormValue("password"))
	data := struct{ Title, Error, Message string }{Title: "Login"}
	if err != nil {
		data.Error = err.Error()
		if err := tmpl["auth/login.html"].Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	token, err := h.sessions.Create(u.ID)
	if err != nil {
		data.Error = err.Error()
		if err := tmpl["auth/login.html"].Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/", HttpOnly: true})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *handler) getLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err == nil {
		h.sessions.Delete(c.Value)
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	}
	http.Redirect(w, r, "/auth/login", http.StatusFound)
}

func (h *handler) getReset(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	data := struct{ Title, Token, Error, Message string }{Title: "Reset Password", Token: token}
	if err := tmpl["auth/reset.html"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) postReset(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token := r.FormValue("token")
	data := struct{ Title, Token, Error, Message string }{Title: "Reset Password", Token: token}
	err := h.auth.ResetPassword(r.Context(), token, r.FormValue("password"))
	if err != nil {
		data.Error = err.Error()
		if err := tmpl["auth/reset.html"].Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *handler) getForgot(w http.ResponseWriter, r *http.Request) {
	data := struct{ Title, Error, Message string }{Title: "Forgot Password"}
	if err := tmpl["auth/forgot.html"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) postForgot(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := h.auth.RequestPasswordReset(r.Context(), r.FormValue("email"))
	data := struct{ Title, Error, Message string }{Title: "Forgot Password"}
	if err != nil {
		data.Error = err.Error()
	} else {
		data.Message = "Password reset email sent"
	}
	if err := tmpl["auth/forgot.html"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) confirmMail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	err := h.auth.ConfirmEmail(r.Context(), token)
	data := struct{ Title, Message string }{Title: "Confirm Email"}
	if err != nil {
		data.Message = "Verification failed: " + err.Error()
	} else {
		data.Message = "Email confirmed"
	}
	if err := tmpl["auth/confirm.html"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) getServerSettings(w http.ResponseWriter, r *http.Request) {
	urlSetting, _ := h.client.Settings.Query().Where(settings.KeyEQ("pdns_api_url")).Only(r.Context())
	keySetting, _ := h.client.Settings.Query().Where(settings.KeyEQ("pdns_api_key")).Only(r.Context())
	data := struct {
		Title      string
		PDNSAPIURL string
		PDNSAPIKey string
		Error      string
		Message    string
	}{Title: "Server Settings"}
	if urlSetting != nil {
		data.PDNSAPIURL = urlSetting.Value
	}
	if keySetting != nil {
		data.PDNSAPIKey = keySetting.Value
	}
	if err := tmpl["settings/server.html"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) postServerSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pdnsURL := r.FormValue("pdns_api_url")
	pdnsKey := r.FormValue("pdns_api_key")
	data := struct {
		Title      string
		PDNSAPIURL string
		PDNSAPIKey string
		Error      string
		Message    string
	}{Title: "Server Settings", PDNSAPIURL: pdnsURL, PDNSAPIKey: pdnsKey}
	if _, err := url.ParseRequestURI(pdnsURL); err != nil {
		data.Error = "invalid URL"
		if err := tmpl["settings/server.html"].Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	if strings.TrimSpace(pdnsKey) == "" {
		data.Error = "API key required"
		if err := tmpl["settings/server.html"].Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	if n, err := h.client.Settings.Update().Where(settings.KeyEQ("pdns_api_url")).SetValue(pdnsURL).Save(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if n == 0 {
		if _, err := h.client.Settings.Create().SetKey("pdns_api_url").SetValue(pdnsURL).Save(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if n, err := h.client.Settings.Update().Where(settings.KeyEQ("pdns_api_key")).SetValue(pdnsKey).Save(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if n == 0 {
		if _, err := h.client.Settings.Create().SetKey("pdns_api_key").SetValue(pdnsKey).Save(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	config.PDNSAPIURL = pdnsURL
	config.PDNSAPIKey = pdnsKey
	data.Message = "Settings saved"
	if err := tmpl["settings/server.html"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
