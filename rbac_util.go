package rbac

import "errors"

func (rbac *Rbac[T]) CheckExtendCircle() error {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()
	for id := range rbac.Roles {
		if err := checkRole(rbac, id); err != nil {
			return err
		}
	}

	return nil
}

func checkRole[T comparable](rbac *Rbac[T], id T) error {
	var dfs func(id T, stk []T) error
	dfs = func(id T, stk []T) error {
		/*
					a stk[nil]
			b stk[a]						c stk[a]
				a stk[a,b] circle 					d stk[a,c] leaf = true

		*/
		// check path
		for _, parentId := range stk {
			if parentId == id {
				return errors.New("circle")
			}
		}

		parents := rbac.Parents[id]
		if len(parents) == 0 {
			return nil
		}

		stk = append(stk, id)
		for pid := range parents {
			if err := dfs(pid, stk); err != nil {
				return err
			}
		}
		return nil
	}

	return dfs(id, nil)
}

// AnyGranted checks if any role has the permission.
func AnyGranted[T comparable](rbac *Rbac[T], roles []IRole[T],
	permission IPermission[T]) (ok bool) {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()
	for _, role := range roles {
		if rbac.IsGranted(role, permission) {
			ok = true
			break
		}
	}
	return
}

// AllGranted checks if all roles have the permission.
func AllGranted[T comparable](rbac *Rbac[T], roles []IRole[T], permission IPermission[T]) (ok bool) {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()
	for _, role := range roles {
		if !rbac.IsGranted(role, permission) {
			return false
		}
	}
	return true
}
