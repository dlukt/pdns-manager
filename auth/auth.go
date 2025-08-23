package auth

import (
	"context"
	"errors"

	"github.com/dlukt/pdns-manager/ent"
	"github.com/dlukt/pdns-manager/ent/user"
	"github.com/rs/xid"
	"golang.org/x/crypto/bcrypt"
)

// Service provides user authentication operations.
type Service struct {
	client *ent.Client
	mailer Mailer
}

// NewService returns a new Service.
func NewService(c *ent.Client, m Mailer) *Service {
	return &Service{client: c, mailer: m}
}

// RegisterInput is used to create a new user.
type RegisterInput struct {
	FirstName string
	LastName  string
	Email     string
	Password  string
}

// Register creates a new user and returns a verification token.
func (s *Service) Register(ctx context.Context, in RegisterInput) (*ent.User, string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", err
	}
	token := xid.New().String()
	u, err := s.client.User.Create().
		SetFirstName(in.FirstName).
		SetLastName(in.LastName).
		SetEmail(in.Email).
		SetPasswordHash(hash).
		SetVerificationToken(token).
		Save(ctx)
	if err != nil {
		return nil, "", err
	}
	if err := s.mailer.SendMail(in.Email, "Verify your email", "Verification token: "+token); err != nil {
		return nil, "", err
	}
	return u, token, nil
}

// ConfirmEmail verifies a user's email with the provided token.
func (s *Service) ConfirmEmail(ctx context.Context, token string) error {
	u, err := s.client.User.Query().Where(user.VerificationTokenEQ(token)).Only(ctx)
	if err != nil {
		return err
	}
	return s.client.User.UpdateOne(u).
		SetEmailVerified(true).
		ClearVerificationToken().
		Exec(ctx)
}

// Login authenticates a user by email and password.
func (s *Service) Login(ctx context.Context, email, password string) (*ent.User, error) {
	u, err := s.client.User.Query().Where(user.EmailEQ(email)).Only(ctx)
	if err != nil {
		return nil, err
	}
	if !u.EmailVerified {
		return nil, errors.New("email not verified")
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return nil, errors.New("invalid credentials")
	}
	return u, nil
}

// UpdateProfile updates the user's profile information.
func (s *Service) UpdateProfile(ctx context.Context, id string, firstName, lastName string) (*ent.User, error) {
	return s.client.User.UpdateOneID(id).
		SetFirstName(firstName).
		SetLastName(lastName).
		Save(ctx)
}

// ChangePassword changes a user's password after verifying the old one.
func (s *Service) ChangePassword(ctx context.Context, id string, oldPassword, newPassword string) error {
	u, err := s.client.User.Get(ctx, id)
	if err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(oldPassword)) != nil {
		return errors.New("invalid password")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.client.User.UpdateOneID(id).SetPasswordHash(hash).Exec(ctx)
}

// ChangeEmail updates the user's email and returns a new verification token.
func (s *Service) ChangeEmail(ctx context.Context, id string, newEmail string) (string, error) {
	token := xid.New().String()
	err := s.client.User.UpdateOneID(id).
		SetEmail(newEmail).
		SetEmailVerified(false).
		SetVerificationToken(token).
		Exec(ctx)
	if err != nil {
		return "", err
	}
	if err := s.mailer.SendMail(newEmail, "Verify your email", "Verification token: "+token); err != nil {
		return "", err
	}
	return token, nil
}

// DeleteAccount removes the user from the database.
func (s *Service) DeleteAccount(ctx context.Context, id string) error {
	return s.client.User.DeleteOneID(id).Exec(ctx)
}

// RequestPasswordReset generates a reset token for the given email.
func (s *Service) RequestPasswordReset(ctx context.Context, email string) (string, error) {
	u, err := s.client.User.Query().Where(user.EmailEQ(email)).Only(ctx)
	if err != nil {
		return "", err
	}
	token := xid.New().String()
	err = s.client.User.UpdateOne(u).SetResetToken(token).Exec(ctx)
	if err != nil {
		return "", err
	}
	if err := s.mailer.SendMail(email, "Password reset", "Reset token: "+token); err != nil {
		return "", err
	}
	return token, nil
}

// ResetPassword resets the user's password using the provided token.
func (s *Service) ResetPassword(ctx context.Context, token, newPassword string) error {
	u, err := s.client.User.Query().Where(user.ResetTokenEQ(token)).Only(ctx)
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.client.User.UpdateOne(u).
		SetPasswordHash(hash).
		ClearResetToken().
		Exec(ctx)
}
