package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
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

// NewHandler returns an http.Handler with application routes.
func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", index)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	return mux
}

func index(w http.ResponseWriter, r *http.Request) {
	data := struct{ Title string }{Title: "PDNS Manager"}
	if err := tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
