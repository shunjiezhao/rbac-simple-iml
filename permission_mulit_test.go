package rbac

import (
	"testing"
)

func TestLayerPermission(t *testing.T) {
	p1 := NewLayerPermission("p1", "::")
	p2 := NewLayerPermission("p2", "::")
	admin := NewLayerPermission("admin", "::")
	admindashboard := NewLayerPermission("admin::dashboard", "::")
	adminpassword := NewLayerPermission("admin::password", "::")

	if !p1.Match(p1) {
		t.Fatalf("`%[1]s` should have the permission `%[1]s`", p1.ID())
	}
	if p1.Match(p2) {
		t.Fatalf("`%s` should not have the permission `%s`", p1.ID(), p2.ID())
	}
	if p1.Match(admin) {
		t.Fatalf("`%s` should not have the permission `%s`", p1.ID(), admin.ID())
	}
	if !admin.Match(admindashboard) { // we are parent
		t.Fatalf("`%s` should have the permission `%s`", admin.ID(), admindashboard.ID())
	}
	if admindashboard.Match(admin) { // son don't equal parent
		t.Fatalf("`%s` should not have the permission `%s`", admindashboard.ID(), admin.ID())
	}
	if adminpassword.Match(admindashboard) { // in one layer,but leaf is not equal
		t.Fatalf("`%s` should not have the permission `%s`", adminpassword.ID(), admindashboard)
	}
}
