package main

import (
	"fmt"
	"rbac"
)

func main() {
	rA := rbac.NewRole("role-a")
	pA := rbac.NewPermission[string]("permission-a")
	rB := rbac.NewRole("role-b")
	pB := rbac.NewPermission[string]("permission-b")
	rC := rbac.NewRole("role-c")
	pC := rbac.NewPermission[string]("permission-c")
	assert := func(err error) {
		if err != nil {
			panic(err)
		}
	}

	Rbac := rbac.New[string]()
	assert(rA.Assign(pA))
	assert(rB.Assign(pB))
	assert(rC.Assign(pC))
	assert(Rbac.Add(rA))
	assert(Rbac.Add(rB))
	assert(Rbac.Add(rC))

	assert(Rbac.SetParents(rA, rB, rC))

	fmt.Println(Rbac.IsGranted(rA, pB))
	fmt.Println(Rbac.IsGranted(rB, pC))

	assert(Rbac.Remove(rA))
	fmt.Println(Rbac.RemoveParent(rA, rB))
	Rbac.CheckExtendCircle()
}
