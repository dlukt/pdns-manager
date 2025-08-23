package schema

import (
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
		field.String("first_name"),
		field.String("last_name"),
		field.String("email").Unique(),
		field.String("password_hash"),
		field.Bool("email_verified").Default(false),
		field.String("verification_token").Optional().Nillable(),
		field.String("reset_token").Optional().Nillable(),
	}
}
