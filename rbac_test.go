package rbac

var (
	rA = NewRole("role-a")
	pA = NewPermission[string]("permission-a")
	rB = NewRole("role-b")
	pB = NewPermission[string]("permission-b")
	rC = NewRole("role-c")
	pC = NewPermission[string]("permission-c")

	rbac  *Rbac[string]
	pAll  = NewPermission[string]("permission-all")
	pNone = NewPermission[string]("permission-none")
)
