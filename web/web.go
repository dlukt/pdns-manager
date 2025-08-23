package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/dlukt/pdns-manager/auth"
)

//go:embed templates/*.html static/*
var contentFS embed.FS

var (
	tmpl     = template.Must(template.ParseFS(contentFS, "templates/*.html"))
	staticFS = mustStatic()
)

func mustStatic() fs.FS {
	s, err := fs.Sub(contentFS, "static")
	if err != nil {
		panic(err)
	}
	return s
}

type handler struct {
	auth *auth.Service
}

// NewHandler returns an http.Handler with application routes.
func NewHandler(a *auth.Service) http.Handler {
	h := &handler{auth: a}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", h.index)
	mux.HandleFunc("GET /register", h.getRegister)
	mux.HandleFunc("POST /register", h.postRegister)
	mux.HandleFunc("GET /login", h.getLogin)
	mux.HandleFunc("POST /login", h.postLogin)
	mux.HandleFunc("GET /reset", h.getReset)
	mux.HandleFunc("POST /reset", h.postReset)
	mux.HandleFunc("GET /forgot", h.getForgot)
	mux.HandleFunc("POST /forgot", h.postForgot)
	mux.HandleFunc("GET /confirm_mail", h.confirmMail)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	return mux
}

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	data := struct{ Title string }{Title: "PDNS Manager"}
	if err := tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) getRegister(w http.ResponseWriter, r *http.Request) {
	data := struct{ Title, Error, Message string }{Title: "Register"}
	if err := tmpl.ExecuteTemplate(w, "register.html", data); err != nil {
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
	if err := tmpl.ExecuteTemplate(w, "register.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) getLogin(w http.ResponseWriter, r *http.Request) {
	data := struct{ Title, Error, Message string }{Title: "Login"}
	if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) postLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := h.auth.Login(r.Context(), r.FormValue("email"), r.FormValue("password"))
	data := struct{ Title, Error, Message string }{Title: "Login"}
	if err != nil {
		data.Error = err.Error()
	} else {
		data.Message = "Login successful"
	}
	if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) getReset(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	data := struct{ Title, Token, Error, Message string }{Title: "Reset Password", Token: token}
	if err := tmpl.ExecuteTemplate(w, "reset.html", data); err != nil {
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
	if err := tmpl.ExecuteTemplate(w, "reset.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) getForgot(w http.ResponseWriter, r *http.Request) {
	data := struct{ Title, Error, Message string }{Title: "Forgot Password"}
	if err := tmpl.ExecuteTemplate(w, "forgot.html", data); err != nil {
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
	if err := tmpl.ExecuteTemplate(w, "forgot.html", data); err != nil {
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
	if err := tmpl.ExecuteTemplate(w, "confirm.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
