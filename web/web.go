package web

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"unicode"

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

var errUnauthenticated = errors.New("unauthenticated")

type pdnsClient interface {
	ListServers(ctx context.Context) ([]pdns.Server, error)
	ListZones(ctx context.Context, serverID string) ([]pdns.Zone, error)
	GetZone(ctx context.Context, serverID, zoneID string) (*pdns.Zone, error)
	CreateZone(ctx context.Context, serverID string, zone pdns.Zone) (*pdns.Zone, error)
	DeleteZone(ctx context.Context, serverID, zoneID string) error
	SearchData(ctx context.Context, serverID, q string, max int, objectType string) ([]pdns.SearchResult, error)
	ModifyRRsets(ctx context.Context, serverID, zoneID string, rrsets []pdns.RRSet) error
}

// NewHandler returns an http.Handler with application routes.
func NewHandler(c *ent.Client, a *auth.Service, s *session.Store, p pdnsClient) http.Handler {
	h := &handler{auth: a, sessions: s, client: c, pdnsClient: p, zoneKinds: []string{"Native", "Master", "Slave"}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", h.index)
	mux.HandleFunc("GET /zones", h.listZones)
	mux.HandleFunc("GET /zones/{serverID}/{zoneID}", h.getZoneRecords)
	mux.HandleFunc("POST /zones/{serverID}/{zoneID}/records", h.postZoneRecordAdd)
	mux.HandleFunc("POST /zones/{serverID}/{zoneID}/records/update", h.postZoneRecordUpdate)
	mux.HandleFunc("POST /zones/{serverID}/{zoneID}/records/delete", h.postZoneRecordDelete)
	mux.HandleFunc("GET /search", h.getSearch)
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
	mux.HandleFunc("GET /profile", h.getProfile)
	mux.HandleFunc("POST /profile", h.postProfileUpdate)
	mux.HandleFunc("POST /profile/password", h.postProfilePassword)
	mux.HandleFunc("POST /profile/email", h.postProfileEmail)
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

func (h *handler) currentUser(r *http.Request) (*ent.User, error) {
	c, err := r.Cookie("session")
	if err != nil {
		return nil, errUnauthenticated
	}
	id, ok := h.sessions.Get(c.Value)
	if !ok {
		return nil, errUnauthenticated
	}
	u, err := h.client.User.Get(r.Context(), id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errUnauthenticated
		}
		return nil, err
	}
	return u, nil
}

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	if h.pdnsClient != nil {
		http.Redirect(w, r, "/zones", http.StatusFound)
		return
	}
	data := struct{ Title string }{Title: "PDNS Manager"}
	if err := tmpl["index.html"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type zonesIndexView struct {
	Title            string
	Servers          []pdns.Server
	SelectedServerID string
	Zones            []pdns.Zone
	Success          string
	Error            string
}

type searchView struct {
	Title            string
	Servers          []pdns.Server
	SelectedServerID string
	Query            string
	ObjectType       string
	Max              int
	Results          []pdns.SearchResult
	Error            string
}

type zoneRecordsView struct {
	Title    string
	ServerID string
	ZoneID   string
	Zone     *pdns.Zone
	Form     recordForm
	Error    string
	Success  string
}

type profileView struct {
	Title           string
	User            *ent.User
	ProfileSuccess  string
	ProfileError    string
	PasswordSuccess string
	PasswordError   string
	EmailSuccess    string
	EmailError      string
}

func (h *handler) renderProfile(w http.ResponseWriter, view profileView) {
	if err := tmpl["profile.html"].Execute(w, view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) renderSearch(w http.ResponseWriter, view searchView) {
	if err := tmpl["search.html"].Execute(w, view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) renderZoneRecords(w http.ResponseWriter, view zoneRecordsView) {
	if err := tmpl["zones/records.html"].Execute(w, view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) getProfile(w http.ResponseWriter, r *http.Request) {
	u, err := h.currentUser(r)
	if err != nil {
		if errors.Is(err, errUnauthenticated) {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	view := profileView{Title: "Profile", User: u}
	h.renderProfile(w, view)
}

func (h *handler) postProfileUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := h.currentUser(r)
	if err != nil {
		if errors.Is(err, errUnauthenticated) {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	view := profileView{Title: "Profile", User: u}
	firstName := strings.TrimSpace(r.FormValue("first_name"))
	lastName := strings.TrimSpace(r.FormValue("last_name"))
	if firstName == "" || lastName == "" {
		view.ProfileError = "First and last name are required."
		h.renderProfile(w, view)
		return
	}
	updated, err := h.auth.UpdateProfile(r.Context(), u.ID, firstName, lastName)
	if err != nil {
		view.ProfileError = err.Error()
		h.renderProfile(w, view)
		return
	}
	view.User = updated
	view.ProfileSuccess = "Profile updated successfully."
	h.renderProfile(w, view)
}

func (h *handler) postProfilePassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := h.currentUser(r)
	if err != nil {
		if errors.Is(err, errUnauthenticated) {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	view := profileView{Title: "Profile", User: u}
	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")
	if newPassword != confirmPassword {
		view.PasswordError = "New password confirmation does not match."
		h.renderProfile(w, view)
		return
	}
	if len(newPassword) < 8 {
		view.PasswordError = "New password must be at least 8 characters."
		h.renderProfile(w, view)
		return
	}
	if err := h.auth.ChangePassword(r.Context(), u.ID, currentPassword, newPassword); err != nil {
		if err.Error() == "invalid password" {
			view.PasswordError = "Current password is incorrect."
		} else {
			view.PasswordError = err.Error()
		}
		h.renderProfile(w, view)
		return
	}
	view.PasswordSuccess = "Password updated successfully."
	h.renderProfile(w, view)
}

func (h *handler) postProfileEmail(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := h.currentUser(r)
	if err != nil {
		if errors.Is(err, errUnauthenticated) {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	view := profileView{Title: "Profile", User: u}
	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		view.EmailError = "Email address is required."
		h.renderProfile(w, view)
		return
	}
	if _, err := mail.ParseAddress(email); err != nil {
		view.EmailError = "Enter a valid email address."
		h.renderProfile(w, view)
		return
	}
	if _, err := h.auth.ChangeEmail(r.Context(), u.ID, email); err != nil {
		view.EmailError = err.Error()
		h.renderProfile(w, view)
		return
	}
	updated, err := h.client.User.Get(r.Context(), u.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	view.User = updated
	view.EmailSuccess = "A verification email has been sent to your new address."
	h.renderProfile(w, view)
}
func (h *handler) listZones(w http.ResponseWriter, r *http.Request) {
	if h.pdnsClient == nil {
		http.Error(w, "PowerDNS client not configured", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()
	q := r.URL.Query()
	successMsg := q.Get("success")
	errorMsg := q.Get("error")
	servers, err := h.pdnsClient.ListServers(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to load servers: %v", err), http.StatusBadGateway)
		return
	}
	if len(servers) == 0 {
		data := zonesIndexView{Title: "Zones", Servers: servers, Success: successMsg, Error: errorMsg}
		if err := tmpl["zones/index.html"].Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	selected := q.Get("server")
	if selected == "" {
		selected = servers[0].ID
	} else {
		found := false
		for _, s := range servers {
			if s.ID == selected {
				found = true
				break
			}
		}
		if !found {
			http.NotFound(w, r)
			return
		}
	}
	zones, err := h.pdnsClient.ListZones(ctx, selected)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to load zones: %v", err), http.StatusBadGateway)
		return
	}
	data := zonesIndexView{
		Title:            "Zones",
		Servers:          servers,
		SelectedServerID: selected,
		Zones:            zones,
		Success:          successMsg,
		Error:            errorMsg,
	}
	if err := tmpl["zones/index.html"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) getSearch(w http.ResponseWriter, r *http.Request) {
	data := searchView{Title: "Global Search"}
	if h.pdnsClient == nil {
		data.Error = "PowerDNS client not configured"
		h.renderSearch(w, data)
		return
	}
	servers, err := h.listServers(r)
	if err != nil {
		data.Error = err.Error()
		h.renderSearch(w, data)
		return
	}
	data.Servers = servers

	query := r.URL.Query()
	data.Query = strings.TrimSpace(query.Get("q"))
	objectType, typeErr := normalizeSearchObjectType(query.Get("object_type"))
	if typeErr != "" {
		data.Error = typeErr
		data.ObjectType = strings.TrimSpace(query.Get("object_type"))
		h.renderSearch(w, data)
		return
	}
	data.ObjectType = objectType

	maxRaw := strings.TrimSpace(query.Get("max"))
	if maxRaw != "" {
		max, err := strconv.Atoi(maxRaw)
		if err != nil || max <= 0 {
			data.Error = "Max results must be a positive number."
			h.renderSearch(w, data)
			return
		}
		data.Max = max
	}

	if len(servers) == 0 {
		h.renderSearch(w, data)
		return
	}

	selected := strings.TrimSpace(query.Get("server"))
	if selected == "" {
		selected = servers[0].ID
	} else if !h.serverExists(servers, selected) {
		http.NotFound(w, r)
		return
	}
	data.SelectedServerID = selected

	if data.Query != "" {
		results, err := h.pdnsClient.SearchData(r.Context(), selected, data.Query, data.Max, data.ObjectType)
		if err != nil {
			data.Error = err.Error()
		} else {
			data.Results = results
		}
	}
	if data.Error != "" {
		h.renderSearch(w, data)
		return
	}
	h.renderSearch(w, data)
}

func (h *handler) getZoneRecords(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("serverID")
	zoneID := r.PathValue("zoneID")
	if serverID == "" || zoneID == "" {
		http.Error(w, "missing identifiers", http.StatusBadRequest)
		return
	}
	flash := r.URL.Query()
	successMsg := strings.TrimSpace(flash.Get("success"))
	errorMsg := strings.TrimSpace(flash.Get("error"))
	data := zoneRecordsView{
		Title:    "Zone Records",
		ServerID: serverID,
		ZoneID:   zoneID,
		Form:     recordForm{TTL: "3600"},
		Success:  successMsg,
		Error:    errorMsg,
	}
	if h.pdnsClient == nil {
		if data.Error == "" {
			data.Error = "PowerDNS client not configured"
		}
		h.renderZoneRecords(w, data)
		return
	}
	servers, err := h.listServers(r)
	if err != nil {
		if data.Error == "" {
			data.Error = err.Error()
		}
		h.renderZoneRecords(w, data)
		return
	}
	if !h.serverExists(servers, serverID) {
		http.NotFound(w, r)
		return
	}
	zone, err := h.pdnsClient.GetZone(r.Context(), serverID, zoneID)
	if err != nil {
		if data.Error == "" {
			data.Error = err.Error()
		}
		h.renderZoneRecords(w, data)
		return
	}
	data.Zone = zone
	if zone.Name != "" {
		data.Title = "Zone " + zone.Name
	}
	h.renderZoneRecords(w, data)
}

type recordForm struct {
	Name    string
	Type    string
	TTL     string
	Content string
}

type recordUpdateForm struct {
	Name     string
	Type     string
	TTL      string
	OldValue string
	NewValue string
}

var validRecordTypes = map[string]struct{}{
	"A": {}, "AAAA": {}, "AFSDB": {}, "ALIAS": {}, "CAA": {}, "CERT": {}, "CNAME": {},
	"DHCID": {}, "DNSKEY": {}, "DS": {}, "EUI48": {}, "EUI64": {}, "HINFO": {},
	"HTTPS": {}, "KEY": {}, "LOC": {}, "MX": {}, "NAPTR": {}, "NS": {}, "OPENPGPKEY": {},
	"PTR": {}, "RRSIG": {}, "SMIMEA": {}, "SOA": {}, "SRV": {}, "SSHFP": {},
	"SVCB": {}, "TLSA": {}, "TSIG": {}, "TXT": {}, "URI": {},
}

type recordActionView struct {
	Title    string
	ServerID string
	ZoneID   string
	Zone     *pdns.Zone
	Form     recordForm
	Error    string
}

func (h *handler) postZoneRecordAdd(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("serverID")
	zoneID := r.PathValue("zoneID")
	if serverID == "" || zoneID == "" {
		http.Error(w, "missing identifiers", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	form := recordForm{
		Name:    strings.TrimSpace(r.FormValue("name")),
		Type:    strings.ToUpper(strings.TrimSpace(r.FormValue("type"))),
		TTL:     strings.TrimSpace(r.FormValue("ttl")),
		Content: strings.TrimSpace(r.FormValue("content")),
	}
	data := recordActionView{
		Title:    "Zone Records",
		ServerID: serverID,
		ZoneID:   zoneID,
		Form:     form,
	}
	if form.Name == "" {
		data.Error = "Record name is required."
		h.renderZoneRecordAction(w, r, data)
		return
	}
	if form.Type == "" {
		data.Error = "Record type is required."
		h.renderZoneRecordAction(w, r, data)
		return
	}
	if !isRecordTypeAllowed(form.Type) {
		data.Error = "Record type is not supported."
		h.renderZoneRecordAction(w, r, data)
		return
	}
	if form.Content == "" {
		data.Error = "Record content is required."
		h.renderZoneRecordAction(w, r, data)
		return
	}
	if err := validateRecordContent(form.Type, form.Content); err != nil {
		data.Error = err.Error()
		h.renderZoneRecordAction(w, r, data)
		return
	}
	if h.pdnsClient == nil {
		data.Error = "PowerDNS client not configured"
		h.renderZoneRecordAction(w, r, data)
		return
	}
	zone, err := h.pdnsClient.GetZone(r.Context(), serverID, zoneID)
	if err != nil {
		data.Error = err.Error()
		h.renderZoneRecordAction(w, r, data)
		return
	}
	data.Zone = zone
	if err := ensureRecordInZone(zone, form.Name, form.Type); err != nil {
		data.Error = err.Error()
		h.renderZoneRecordAction(w, r, data)
		return
	}
	normalizedName := normalizeRecordName(form.Name, zone.Name)
	existingRRset, _ := findRRset(zone, normalizedName, form.Type)
	defaultTTL := 3600
	records := make([]pdns.Record, 0)
	if existingRRset != nil {
		defaultTTL = existingRRset.TTL
		records = append(records, existingRRset.Records...)
	}
	if recordExists(records, form.Content) {
		data.Error = "Record already exists."
		h.renderZoneRecordAction(w, r, data)
		return
	}
	ttl, err := parseTTL(form.TTL, defaultTTL)
	if err != nil {
		data.Error = err.Error()
		h.renderZoneRecordAction(w, r, data)
		return
	}
	records = append(records, pdns.Record{Content: form.Content, Disabled: false})
	rrset := pdns.RRSet{
		Name:       normalizedName,
		Type:       form.Type,
		TTL:        ttl,
		Changetype: "REPLACE",
		Records:    records,
	}
	if err := h.pdnsClient.ModifyRRsets(r.Context(), serverID, zoneID, []pdns.RRSet{rrset}); err != nil {
		data.Error = err.Error()
		h.renderZoneRecordAction(w, r, data)
		return
	}
	params := url.Values{}
	params.Set("success", "Record added successfully.")
	http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
}

func (h *handler) postZoneRecordDelete(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("serverID")
	zoneID := r.PathValue("zoneID")
	if serverID == "" || zoneID == "" {
		http.Error(w, "missing identifiers", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	typeValue := strings.ToUpper(strings.TrimSpace(r.FormValue("type")))
	content := strings.TrimSpace(r.FormValue("content"))
	if name == "" || typeValue == "" {
		http.Error(w, "missing record identifiers", http.StatusBadRequest)
		return
	}
	if !isRecordTypeAllowed(typeValue) {
		http.Error(w, "unsupported record type", http.StatusBadRequest)
		return
	}
	if h.pdnsClient == nil {
		params := url.Values{}
		params.Set("error", "PowerDNS client not configured")
		http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
		return
	}
	zone, err := h.pdnsClient.GetZone(r.Context(), serverID, zoneID)
	if err != nil {
		params := url.Values{}
		params.Set("error", err.Error())
		http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
		return
	}
	if err := ensureRecordInZone(zone, name, typeValue); err != nil {
		params := url.Values{}
		params.Set("error", err.Error())
		http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
		return
	}
	normalizedName := normalizeRecordName(name, zone.Name)
	if content != "" {
		rrset, err := findRRset(zone, normalizedName, typeValue)
		if err != nil {
			params := url.Values{}
			params.Set("error", err.Error())
			http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
			return
		}
		remaining := make([]pdns.Record, 0, len(rrset.Records))
		removed := false
		for _, record := range rrset.Records {
			if record.Content == content {
				removed = true
				continue
			}
			remaining = append(remaining, record)
		}
		if !removed {
			params := url.Values{}
			params.Set("error", "Record content not found.")
			http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
			return
		}
		if len(remaining) == 0 {
			rrsetDelete := pdns.RRSet{
				Name:       normalizedName,
				Type:       typeValue,
				Changetype: "DELETE",
				Records:    []pdns.Record{},
			}
			if err := h.pdnsClient.ModifyRRsets(r.Context(), serverID, zoneID, []pdns.RRSet{rrsetDelete}); err != nil {
				params := url.Values{}
				params.Set("error", err.Error())
				http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
				return
			}
			params := url.Values{}
			params.Set("success", "Record deleted successfully.")
			http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
			return
		}
		rrsetReplace := pdns.RRSet{
			Name:       normalizedName,
			Type:       typeValue,
			TTL:        rrset.TTL,
			Changetype: "REPLACE",
			Records:    remaining,
		}
		if err := h.pdnsClient.ModifyRRsets(r.Context(), serverID, zoneID, []pdns.RRSet{rrsetReplace}); err != nil {
			params := url.Values{}
			params.Set("error", err.Error())
			http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
			return
		}
		params := url.Values{}
		params.Set("success", "Record deleted successfully.")
		http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
		return
	}
	if _, err := findRRset(zone, normalizedName, typeValue); err != nil {
		params := url.Values{}
		params.Set("error", err.Error())
		http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
		return
	}
	rrset := pdns.RRSet{
		Name:       normalizedName,
		Type:       typeValue,
		Changetype: "DELETE",
		Records:    []pdns.Record{},
	}
	if err := h.pdnsClient.ModifyRRsets(r.Context(), serverID, zoneID, []pdns.RRSet{rrset}); err != nil {
		params := url.Values{}
		params.Set("error", err.Error())
		http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
		return
	}
	params := url.Values{}
	params.Set("success", "Record deleted successfully.")
	http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
}

func (h *handler) postZoneRecordUpdate(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("serverID")
	zoneID := r.PathValue("zoneID")
	if serverID == "" || zoneID == "" {
		http.Error(w, "missing identifiers", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	form := recordUpdateForm{
		Name:     strings.TrimSpace(r.FormValue("name")),
		Type:     strings.ToUpper(strings.TrimSpace(r.FormValue("type"))),
		TTL:      strings.TrimSpace(r.FormValue("ttl")),
		OldValue: strings.TrimSpace(r.FormValue("old_value")),
		NewValue: strings.TrimSpace(r.FormValue("new_value")),
	}
	if form.Name == "" || form.Type == "" || form.OldValue == "" {
		http.Error(w, "missing record identifiers", http.StatusBadRequest)
		return
	}
	if !isRecordTypeAllowed(form.Type) {
		http.Error(w, "unsupported record type", http.StatusBadRequest)
		return
	}
	if form.NewValue == "" {
		params := url.Values{}
		params.Set("error", "New record value is required.")
		http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
		return
	}
	if err := validateRecordContent(form.Type, form.NewValue); err != nil {
		params := url.Values{}
		params.Set("error", err.Error())
		http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
		return
	}
	if h.pdnsClient == nil {
		params := url.Values{}
		params.Set("error", "PowerDNS client not configured")
		http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
		return
	}
	zone, err := h.pdnsClient.GetZone(r.Context(), serverID, zoneID)
	if err != nil {
		params := url.Values{}
		params.Set("error", err.Error())
		http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
		return
	}
	if err := ensureRecordInZone(zone, form.Name, form.Type); err != nil {
		params := url.Values{}
		params.Set("error", err.Error())
		http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
		return
	}
	normalizedName := normalizeRecordName(form.Name, zone.Name)
	rrset, err := findRRset(zone, normalizedName, form.Type)
	if err != nil {
		params := url.Values{}
		params.Set("error", err.Error())
		http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
		return
	}
	updatedRecords := make([]pdns.Record, 0, len(rrset.Records))
	updated := false
	for _, record := range rrset.Records {
		if record.Content == form.OldValue {
			updated = true
			if recordExists(updatedRecords, form.NewValue) {
				params := url.Values{}
				params.Set("error", "Record already exists.")
				http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
				return
			}
			updatedRecords = append(updatedRecords, pdns.Record{Content: form.NewValue, Disabled: record.Disabled})
			continue
		}
		updatedRecords = append(updatedRecords, record)
	}
	if !updated {
		params := url.Values{}
		params.Set("error", "Record content not found.")
		http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
		return
	}
	newTTL, err := parseTTL(form.TTL, rrset.TTL)
	if err != nil {
		params := url.Values{}
		params.Set("error", err.Error())
		http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
		return
	}
	updatedRRset := pdns.RRSet{
		Name:       normalizedName,
		Type:       rrset.Type,
		TTL:        newTTL,
		Changetype: "REPLACE",
		Records:    updatedRecords,
	}
	if err := h.pdnsClient.ModifyRRsets(r.Context(), serverID, zoneID, []pdns.RRSet{updatedRRset}); err != nil {
		params := url.Values{}
		params.Set("error", err.Error())
		http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
		return
	}
	params := url.Values{}
	params.Set("success", "Record updated successfully.")
	http.Redirect(w, r, "/zones/"+url.PathEscape(serverID)+"/"+url.PathEscape(zoneID)+"?"+params.Encode(), http.StatusFound)
}

func (h *handler) renderZoneRecordAction(w http.ResponseWriter, r *http.Request, view recordActionView) {
	if view.Zone == nil {
		zone, err := h.pdnsClient.GetZone(r.Context(), view.ServerID, view.ZoneID)
		if err != nil {
			view.Error = err.Error()
		} else {
			view.Zone = zone
		}
	}
	if view.Form.TTL == "" {
		view.Form.TTL = "3600"
	}
	recordsView := zoneRecordsView{
		Title:    view.Title,
		ServerID: view.ServerID,
		ZoneID:   view.ZoneID,
		Zone:     view.Zone,
		Form:     view.Form,
		Error:    view.Error,
	}
	if recordsView.Title == "" {
		recordsView.Title = "Zone Records"
	}
	h.renderZoneRecords(w, recordsView)
}

func parseTTL(input string, fallback int) (int, error) {
	value := strings.TrimSpace(input)
	if value == "" {
		if fallback > 0 {
			return fallback, nil
		}
		return 3600, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("TTL must be a positive number")
	}
	return parsed, nil
}

func ensureDotSuffix(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return trimmed
	}
	if strings.HasSuffix(trimmed, ".") {
		return trimmed
	}
	return trimmed + "."
}

func normalizeRecordName(name, zoneName string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return trimmed
	}
	if strings.EqualFold(trimmed, "@") {
		return ensureDotSuffix(zoneName)
	}
	normalized := ensureDotSuffix(trimmed)
	zoneValue := ensureDotSuffix(strings.TrimSpace(zoneName))
	if zoneValue != "" && !strings.HasSuffix(strings.ToLower(normalized), strings.ToLower(zoneValue)) {
		if strings.HasSuffix(normalized, ".") {
			normalized = normalized + zoneValue
		} else {
			normalized = normalized + "." + zoneValue
		}
		normalized = ensureDotSuffix(normalized)
	}
	return normalized
}

func findRRset(zone *pdns.Zone, name, recordType string) (*pdns.RRSet, error) {
	if zone == nil {
		return nil, fmt.Errorf("zone not found")
	}
	for i := range zone.RRsets {
		rrset := &zone.RRsets[i]
		if strings.EqualFold(rrset.Name, name) && strings.EqualFold(rrset.Type, recordType) {
			return rrset, nil
		}
	}
	return nil, fmt.Errorf("record set not found")
}

func recordExists(records []pdns.Record, content string) bool {
	for _, record := range records {
		if record.Content == content {
			return true
		}
	}
	return false
}

func ensureRecordInZone(zone *pdns.Zone, name, recordType string) error {
	if zone == nil {
		return fmt.Errorf("zone not found")
	}
	zoneName := strings.TrimSpace(zone.Name)
	if zoneName == "" {
		return nil
	}
	normalizedName := normalizeRecordName(name, zoneName)
	zoneNameNormalized := ensureDotSuffix(zoneName)
	if !strings.EqualFold(normalizedName, zoneNameNormalized) && !strings.HasSuffix(strings.ToLower(normalizedName), strings.ToLower("."+zoneNameNormalized)) {
		return fmt.Errorf("record name must be within zone %s", zoneNameNormalized)
	}
	if recordType == "" {
		return nil
	}
	return nil
}

func isRecordTypeAllowed(recordType string) bool {
	if recordType == "" {
		return false
	}
	_, ok := validRecordTypes[strings.ToUpper(recordType)]
	return ok
}

func validateRecordContent(recordType, content string) error {
	switch recordType {
	case "A":
		if ip := net.ParseIP(content); ip == nil || ip.To4() == nil {
			return fmt.Errorf("A record content must be a valid IPv4 address")
		}
	case "AAAA":
		if ip := net.ParseIP(content); ip == nil || ip.To4() != nil {
			return fmt.Errorf("AAAA record content must be a valid IPv6 address")
		}
	case "CNAME", "NS", "PTR":
		if !strings.HasSuffix(strings.TrimSpace(content), ".") {
			return fmt.Errorf("%s record content must be a fully-qualified domain name ending with a dot", recordType)
		}
	case "SRV":
		fields := strings.Fields(content)
		if len(fields) != 4 {
			return fmt.Errorf("SRV record content must be: priority weight port target")
		}
		for i := 0; i < 3; i++ {
			if _, err := strconv.Atoi(fields[i]); err != nil {
				return fmt.Errorf("SRV record content must include numeric priority, weight, and port")
			}
		}
		if !strings.HasSuffix(fields[3], ".") {
			return fmt.Errorf("SRV record target must be a fully-qualified domain name ending with a dot")
		}
	case "MX":
		fields := strings.Fields(content)
		if len(fields) != 2 {
			return fmt.Errorf("MX record content must be: priority target")
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			return fmt.Errorf("MX record priority must be numeric")
		}
		if !strings.HasSuffix(fields[1], ".") {
			return fmt.Errorf("MX record target must be a fully-qualified domain name ending with a dot")
		}
	}
	return nil
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
	defaultKind := ""
	if len(h.zoneKinds) > 0 {
		defaultKind = h.zoneKinds[0]
	}
	data := zonePageData{
		Title:       "Create Zone",
		FieldErrors: map[string]string{},
		Form: zoneForm{
			Kind: defaultKind,
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
	if form.Kind == "" && len(h.zoneKinds) > 0 {
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
	if h.pdnsClient == nil {
		data.Error = "PowerDNS client not configured"
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
	params := url.Values{}
	params.Set("success", fmt.Sprintf("Zone %s created successfully.", form.Name))
	if form.ServerID != "" {
		params.Set("server", form.ServerID)
	}
	http.Redirect(w, r, "/zones?"+params.Encode(), http.StatusFound)
}

func (h *handler) postZoneDelete(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("serverID")
	zoneID := r.PathValue("zoneID")
	if serverID == "" || zoneID == "" {
		http.Error(w, "missing identifiers", http.StatusBadRequest)
		return
	}
	params := url.Values{}
	if serverID != "" {
		params.Set("server", serverID)
	}
	if h.pdnsClient == nil {
		params.Set("error", "PowerDNS client is not configured")
		http.Redirect(w, r, "/zones?"+params.Encode(), http.StatusFound)
		return
	}
	if err := h.pdnsClient.DeleteZone(r.Context(), serverID, zoneID); err != nil {
		params.Set("error", err.Error())
		http.Redirect(w, r, "/zones?"+params.Encode(), http.StatusFound)
		return
	}
	params.Set("success", fmt.Sprintf("Zone %s deleted successfully.", zoneID))
	http.Redirect(w, r, "/zones?"+params.Encode(), http.StatusFound)
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
	allowed := h.zoneKinds
	if len(allowed) == 0 {
		allowed = []string{"Native", "Master", "Slave"}
	}
	for _, option := range allowed {
		if strings.EqualFold(option, kind) {
			return option, ""
		}
	}
	return kind, "Invalid zone kind."
}

func normalizeSearchObjectType(objectType string) (string, string) {
	value := strings.ToLower(strings.TrimSpace(objectType))
	switch value {
	case "", "all":
		return "", ""
	case "record", "zone":
		return value, ""
	default:
		return value, "Object type must be record or zone."
	}
}

func parseMasters(input string) []string {
	if input == "" {
		return nil
	}
	fields := strings.FieldsFunc(input, func(r rune) bool {
		switch r {
		case ',', ';', '\n', '\r', '\t':
			return true
		default:
			return unicode.IsSpace(r)
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
