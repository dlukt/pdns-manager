package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"strings"

	"github.com/dlukt/pdns-manager/auth"
	"github.com/dlukt/pdns-manager/session"
)

//go:embed templates/*.html templates/auth/*.html static/*
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

func mustTemplates() *template.Template {
	t := template.New("")
	err := fs.WalkDir(contentFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".html") {
			return nil
		}
		b, err := contentFS.ReadFile(path)
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(path, "templates/")
		_, err = t.New(name).Parse(string(b))
		return err
	})
	if err != nil {
		panic(err)
	}
	return t
}

type handler struct {
	auth     *auth.Service
	sessions *session.Store
}

// NewHandler returns an http.Handler with application routes.
func NewHandler(a *auth.Service, s *session.Store) http.Handler {
	h := &handler{auth: a, sessions: s}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", h.index)
	mux.HandleFunc("GET /auth/register", h.getRegister)
	mux.HandleFunc("POST /auth/register", h.postRegister)
	mux.HandleFunc("GET /auth/login", h.getLogin)
	mux.HandleFunc("POST /auth/login", h.postLogin)
	mux.HandleFunc("GET /auth/reset", h.getReset)
	mux.HandleFunc("POST /auth/reset", h.postReset)
	mux.HandleFunc("GET /auth/forgot", h.getForgot)
	mux.HandleFunc("POST /auth/forgot", h.postForgot)
	mux.HandleFunc("GET /auth/confirm_mail", h.confirmMail)
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
	if err := tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) getRegister(w http.ResponseWriter, r *http.Request) {
	data := struct{ Title, Error, Message string }{Title: "Register"}
	if err := tmpl.ExecuteTemplate(w, "auth/register.html", data); err != nil {
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
	if err := tmpl.ExecuteTemplate(w, "auth/register.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) getLogin(w http.ResponseWriter, r *http.Request) {
	data := struct{ Title, Error, Message string }{Title: "Login"}
	if err := tmpl.ExecuteTemplate(w, "auth/login.html", data); err != nil {
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
	} else {
		token, e := h.sessions.Create(u.ID)
		if e != nil {
			data.Error = e.Error()
		} else {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/", HttpOnly: true})
			data.Message = "Login successful"
		}
	}
	if err := tmpl.ExecuteTemplate(w, "auth/login.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) getReset(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	data := struct{ Title, Token, Error, Message string }{Title: "Reset Password", Token: token}
	if err := tmpl.ExecuteTemplate(w, "auth/reset.html", data); err != nil {
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
	} else {
		data.Message = "Password reset successful"
	}
	if err := tmpl.ExecuteTemplate(w, "auth/reset.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) getForgot(w http.ResponseWriter, r *http.Request) {
	data := struct{ Title, Error, Message string }{Title: "Forgot Password"}
	if err := tmpl.ExecuteTemplate(w, "auth/forgot.html", data); err != nil {
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
	if err := tmpl.ExecuteTemplate(w, "auth/forgot.html", data); err != nil {
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
	if err := tmpl.ExecuteTemplate(w, "auth/confirm.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
