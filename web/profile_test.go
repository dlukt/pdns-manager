package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"entgo.io/ent/dialect"

	"github.com/dlukt/pdns-manager/auth"
	"github.com/dlukt/pdns-manager/ent"
	"github.com/dlukt/pdns-manager/ent/enttest"
	"github.com/dlukt/pdns-manager/session"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type stubMailer struct{}

func (stubMailer) SendMail(_, _, _ string) error { return nil }

func newProfileTestHandler(t *testing.T) (*handler, *session.Store, *ent.User) {
	t.Helper()
	client := enttest.Open(t, dialect.SQLite, fmt.Sprintf("file:%s?mode=memory&cache=shared&_fk=1", t.Name()))
	t.Cleanup(func() { client.Close() })
	mailer := stubMailer{}
	authSvc := auth.NewService(client, mailer)
	store := session.NewStore([]byte("test-secret"))
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	email := fmt.Sprintf("%s@example.com", strings.ReplaceAll(strings.ToLower(t.Name()), "/", "_"))
	user, err := client.User.Create().
		SetFirstName("Alice").
		SetLastName("Admin").
		SetEmail(email).
		SetEmailVerified(true).
		SetPasswordHash(hash).
		Save(context.Background())
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	h := &handler{auth: authSvc, sessions: store, client: client, zoneKinds: []string{"Native", "Master", "Slave"}}
	return h, store, user
}

func addSessionCookie(t *testing.T, store *session.Store, req *http.Request, userID string) {
	t.Helper()
	token, err := store.Create(userID)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
}

func TestGetProfileRedirectsWhenUnauthenticated(t *testing.T) {
	h, _, _ := newProfileTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/profile", nil)
	res := httptest.NewRecorder()

	h.getProfile(res, req)

	if res.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", res.Code)
	}
	if loc := res.Header().Get("Location"); loc != "/auth/login" {
		t.Fatalf("expected redirect to /auth/login, got %q", loc)
	}
}

func TestGetProfileRendersUser(t *testing.T) {
	h, store, user := newProfileTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/profile", nil)
	addSessionCookie(t, store, req, user.ID)
	res := httptest.NewRecorder()

	h.getProfile(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.Code)
	}
	body := res.Body.String()
	if !strings.Contains(body, user.FirstName) {
		t.Fatalf("response body missing first name: %q", body)
	}
}

func TestPostProfileUpdateValidationError(t *testing.T) {
	h, store, user := newProfileTestHandler(t)
	form := url.Values{
		"first_name": {""},
		"last_name":  {"Admin"},
	}
	req := httptest.NewRequest(http.MethodPost, "/profile", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(t, store, req, user.ID)
	res := httptest.NewRecorder()

	h.postProfileUpdate(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.Code)
	}
	if !strings.Contains(res.Body.String(), "First and last name are required.") {
		t.Fatalf("expected validation error, got %q", res.Body.String())
	}
}

func TestPostProfileUpdateSuccess(t *testing.T) {
	h, store, user := newProfileTestHandler(t)
	form := url.Values{
		"first_name": {"Alicia"},
		"last_name":  {"Manager"},
	}
	req := httptest.NewRequest(http.MethodPost, "/profile", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(t, store, req, user.ID)
	res := httptest.NewRecorder()

	h.postProfileUpdate(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.Code)
	}
	body := res.Body.String()
	if !strings.Contains(body, "Profile updated successfully.") {
		t.Fatalf("expected success message, got %q", body)
	}
	if !strings.Contains(body, "Alicia") {
		t.Fatalf("expected updated name in response, got %q", body)
	}
}

func TestPostProfilePasswordInvalidCurrent(t *testing.T) {
	h, store, user := newProfileTestHandler(t)
	form := url.Values{
		"current_password": {"wrongpass"},
		"new_password":     {"newpassword"},
		"confirm_password": {"newpassword"},
	}
	req := httptest.NewRequest(http.MethodPost, "/profile/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(t, store, req, user.ID)
	res := httptest.NewRecorder()

	h.postProfilePassword(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.Code)
	}
	if !strings.Contains(res.Body.String(), "Current password is incorrect.") {
		t.Fatalf("expected password error, got %q", res.Body.String())
	}
}

func TestPostProfilePasswordSuccess(t *testing.T) {
	h, store, user := newProfileTestHandler(t)
	form := url.Values{
		"current_password": {"secret123"},
		"new_password":     {"changed456"},
		"confirm_password": {"changed456"},
	}
	req := httptest.NewRequest(http.MethodPost, "/profile/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(t, store, req, user.ID)
	res := httptest.NewRecorder()

	h.postProfilePassword(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.Code)
	}
	if !strings.Contains(res.Body.String(), "Password updated successfully.") {
		t.Fatalf("expected success message, got %q", res.Body.String())
	}
}

func TestPostProfileEmailValidation(t *testing.T) {
	h, store, user := newProfileTestHandler(t)
	form := url.Values{
		"email": {"not-an-email"},
	}
	req := httptest.NewRequest(http.MethodPost, "/profile/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(t, store, req, user.ID)
	res := httptest.NewRecorder()

	h.postProfileEmail(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.Code)
	}
	if !strings.Contains(res.Body.String(), "Enter a valid email address.") {
		t.Fatalf("expected validation error, got %q", res.Body.String())
	}
}

func TestPostProfileEmailSuccess(t *testing.T) {
	h, store, user := newProfileTestHandler(t)
	form := url.Values{
		"email": {"new-" + user.ID + "@example.com"},
	}
	req := httptest.NewRequest(http.MethodPost, "/profile/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(t, store, req, user.ID)
	res := httptest.NewRecorder()

	h.postProfileEmail(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.Code)
	}
	body := res.Body.String()
	if !strings.Contains(body, "A verification email has been sent to your new address.") {
		t.Fatalf("expected success message, got %q", body)
	}
	if !strings.Contains(body, "new-"+user.ID+"@example.com") {
		t.Fatalf("expected updated email in response, got %q", body)
	}
}
