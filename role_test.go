package rbac

import "testing"

func TestRole(t *testing.T) {
	rA := NewRole("role-a")
	if err := rA.Assign(NewPermission("permission-a")); err != nil {
		t.Fatal(err)
	}
	if !rA.Permit(NewPermission("permission-a")) {
		t.Fatal("[permission-a] should permit to rA")
	}
	if len(rA.Permissions()) != 1 {
		t.Fatal("[a] should have one permission")
	}

	if err := rA.Revoke(NewPermission("permission-a")); err != nil {
		t.Fatal(err)
	}
	if rA.Permit(NewPermission("permission-a")) {
		t.Fatal("[permission-a] should not permit to rA")
	}
	if len(rA.Permissions()) != 0 {
		t.Fatal("[a] should not have any permission")
	}
}
