# simple-rbac-iml

## todo
-[ ] impl storage
## permission
```go
pA := rbac.NewPermission[string]("permission-a") // create permission
```

## role
```go
rA := rbac.NewRole("role-a") // create role
pA := rbac.NewPermission[string]("permission-a") 
assert(rA.Assign(pA)) // add permission to roleA
rB := rbac.NewRole("role-b")
pB := rbac.NewPermission[string]("permission-b")

rbac := rbac.New[string]() // role manager
rB.Assign(pB)
rbac.Add(rA)
rbac.Add(rB)

rbac.SetParents(rA, rB) // rb is a parent of ra

fmt.Println(rbac.IsGranted(rA, pB))

assert(rbac.Remove(rA))
rbac.RemoveParent(rA, rB) // remove extend to ra

rbac.CheckExtendCircle() // check have  extend circle ?
```