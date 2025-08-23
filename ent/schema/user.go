package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/rs/xid"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			DefaultFunc(func() string { return xid.New().String() }).
			Unique().
			Immutable(),
		field.Time("create_time").Default(time.Now).Immutable(),
		field.Time("update_time").Default(time.Now).UpdateDefault(time.Now).Optional(),
		field.String("first_name").Optional(),
		field.String("last_name").Optional(),
		field.String("email").Unique(),
		field.Bytes("password_hash"),
		field.Bool("email_verified").Default(false),
		field.String("verification_token").Optional().Nillable(),
		field.String("reset_token").Optional().Nillable(),
	}
}
