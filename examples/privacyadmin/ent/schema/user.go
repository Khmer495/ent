// Copyright 2019-present Facebook Inc. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/examples/privacyadmin/ent/entprivacy"
	"entgo.io/ent/examples/privacyadmin/rule"
	"entgo.io/ent/schema/field"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			Default("Unknown"),
	}
}

// Policy defines the privacy policy of the User.
func (User) Policy() ent.Policy {
	return entprivacy.Policy{
		Mutation: entprivacy.MutationPolicy{
			rule.DenyIfNoViewer(),
			rule.AllowIfAdmin(),
			entprivacy.AlwaysDenyRule(),
		},
		Query: entprivacy.QueryPolicy{
			entprivacy.AlwaysAllowRule(),
		},
	}
}
