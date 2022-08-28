// Copyright 2019-present Facebook Inc. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package rule

import (
	"context"

	"entgo.io/ent/examples/privacyadmin/ent/entprivacy"
	"entgo.io/ent/examples/privacyadmin/viewer"
)

// DenyIfNoViewer is a rule that returns deny decision if the viewer is missing in the context.
func DenyIfNoViewer() entprivacy.QueryMutationRule {
	return entprivacy.ContextQueryMutationRule(func(ctx context.Context) error {
		view := viewer.FromContext(ctx)
		if view == nil {
			return entprivacy.Denyf("viewer-context is missing")
		}
		// Skip to the next privacy rule (equivalent to return nil).
		return entprivacy.Skip
	})
}

// AllowIfAdmin is a rule that returns allow decision if the viewer is admin.
func AllowIfAdmin() entprivacy.QueryMutationRule {
	return entprivacy.ContextQueryMutationRule(func(ctx context.Context) error {
		view := viewer.FromContext(ctx)
		if view.Admin() {
			return entprivacy.Allow
		}
		// Skip to the next privacy rule (equivalent to return nil).
		return entprivacy.Skip
	})
}
