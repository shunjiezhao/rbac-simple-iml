package rbac

import (
	"errors"
	"sync"
)

var (
	ErrRoleNotExist = errors.New("role is not exist")
	ErrRoleExist    = errors.New("Role has already existed")
)

/*
	rbac
		roles: check a role exist
		parents: store a map
*/

type (
	Rbac[T comparable] struct {
		mu      sync.RWMutex
		Roles   Roles[T]             `json:"roles"`
		Parents map[T]map[T]struct{} `json:"parents"` // map[RoleId] ParentRole
	}
)

// New returns a RBAC structure.
// The default role structure will be used.
func New[T comparable]() *Rbac[T] {
	return &Rbac[T]{
		Roles:   make(Roles[T]),
		Parents: make(map[T]map[T]struct{}),
	}
}

// SetParents bind `parents` to the role `id`.
func (rbac *Rbac[T]) SetParents(role IRole[T], parentRoles ...IRole[T]) error {
	roleID := role.ID()

	rbac.mu.Lock()
	defer rbac.mu.Unlock()
	if _, ok := rbac.Roles[roleID]; !ok {
		return ErrRoleNotExist
	}

	for _, parent := range parentRoles {
		if _, ok := rbac.Roles[parent.ID()]; !ok {
			return ErrRoleNotExist
		}
	}

	if _, ok := rbac.Parents[roleID]; !ok {
		rbac.Parents[roleID] = make(map[T]struct{})
	}

	for _, parent := range parentRoles {
		rbac.Parents[roleID][parent.ID()] = struct{}{}
	}
	return nil
}

// GetParents return `parents` of the role `id`.
// If the role is not existing, return error
func (rbac *Rbac[T]) GetParents(id T) ([]T, error) {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()
	if _, ok := rbac.Roles[id]; !ok {
		return nil, ErrRoleNotExist
	}
	ids, ok := rbac.Parents[id]
	if !ok {
		return nil, nil
	}
	var parents []T
	for parent := range ids {
		parents = append(parents, parent)
	}
	return parents, nil
}

// RemoveParent unbind the `parent` with the role `id`.
// If the role or the parent is not existing,
// an error will be returned.
func (rbac *Rbac[T]) RemoveParent(role IRole[T], parentRole IRole[T]) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()
	id := role.ID()
	if _, ok := rbac.Roles[id]; !ok {
		return ErrRoleNotExist
	}
	if _, ok := rbac.Roles[parentRole.ID()]; !ok {
		return ErrRoleNotExist
	}
	delete(rbac.Parents[id], parentRole.ID())
	return nil
}

// Add a role
func (rbac *Rbac[T]) Add(r IRole[T]) (err error) {
	rbac.mu.Lock()
	roleID := r.ID()
	if _, ok := rbac.Roles[roleID]; !ok {
		rbac.Roles[roleID] = r
	} else {
		err = ErrRoleExist
	}
	rbac.mu.Unlock()
	return
}

// Remove the role
func (rbac *Rbac[T]) Remove(role IRole[T]) (err error) {
	id := role.ID()
	rbac.mu.Lock()
	defer rbac.mu.Unlock()
	if _, ok := rbac.Roles[id]; ok {
		delete(rbac.Roles, id)
		for rid, parents := range rbac.Parents {
			if rid == id { // delete self
				delete(rbac.Parents, rid)
				continue
			}
			for parent := range parents { // delete self is other parent
				if parent == id {
					delete(rbac.Parents[rid], id)
					break
				}
			}
		}
	} else {
		err = ErrRoleNotExist
	}
	return
}

// Get the role by `id` and a slice of its parents id.
func (rbac *Rbac[T]) Get(id T) (r IRole[T], parents []T, err error) {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()
	var ok bool
	if r, ok = rbac.Roles[id]; ok {
		for parent := range rbac.Parents[id] {
			parents = append(parents, parent)
		}
	} else {
		err = ErrRoleNotExist
	}
	return
}

// IsGranted tests if the role `id` has Permission `p` with the condition `assert`.
func (rbac *Rbac[T]) IsGranted(role IRole[T], p IPermission[T]) (ok bool) {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()
	return rbac.recursionCheck(role.ID(), p)
}

func (rbac *Rbac[T]) recursionCheck(id T, p IPermission[T]) bool {
	if role, ok := rbac.Roles[id]; ok {
		if role.Permit(p) {
			return true
		}
		if parents, ok := rbac.Parents[id]; ok {
			for pID := range parents {
				if _, ok := rbac.Roles[pID]; ok {
					if rbac.recursionCheck(pID, p) {
						return true
					}
				}
			}
		}
	}
	return false
}
