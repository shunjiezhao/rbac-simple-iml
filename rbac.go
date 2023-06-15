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
		roles   Roles[T]             `json:"roles"`
		parents map[T]map[T]struct{} `json:"parents"` // map[RoleId] ParentRole
	}
	// AssertionFunc supplies more fine-grained permission controls.
	AssertionFunc[T comparable] func(*Rbac[T], T, IPermission[T]) bool
)

// New returns a RBAC structure.
// The default role structure will be used.
func New[T comparable]() *Rbac[T] {
	return &Rbac[T]{
		roles:   make(Roles[T]),
		parents: make(map[T]map[T]struct{}),
	}
}

// SetParents bind `parents` to the role `id`.
func (rbac *Rbac[T]) SetParents(role IRole[T], parentRoles ...IRole[T]) error {
	roleID := role.ID()

	rbac.mu.Lock()
	defer rbac.mu.Unlock()
	if _, ok := rbac.roles[roleID]; !ok {
		return ErrRoleNotExist
	}

	for _, parent := range parentRoles {
		if _, ok := rbac.roles[parent.ID()]; !ok {
			return ErrRoleNotExist
		}
	}

	if _, ok := rbac.parents[roleID]; !ok {
		rbac.parents[roleID] = make(map[T]struct{})
	}

	for _, parent := range parentRoles {
		rbac.parents[roleID][parent.ID()] = struct{}{}
	}
	return nil
}

// GetParents return `parents` of the role `id`.
// If the role is not existing, return error
func (rbac *Rbac[T]) GetParents(id T) ([]T, error) {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()
	if _, ok := rbac.roles[id]; !ok {
		return nil, ErrRoleNotExist
	}
	ids, ok := rbac.parents[id]
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
func (rbac *Rbac[T]) RemoveParent(id T, parent T) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()
	if _, ok := rbac.roles[id]; !ok {
		return ErrRoleNotExist
	}
	if _, ok := rbac.roles[parent]; !ok {
		return ErrRoleNotExist
	}
	delete(rbac.parents[id], parent)
	return nil
}

// Add a role
func (rbac *Rbac[T]) Add(r IRole[T]) (err error) {
	rbac.mu.Lock()
	roleID := r.ID()
	if _, ok := rbac.roles[roleID]; !ok {
		rbac.roles[roleID] = r
	} else {
		err = ErrRoleExist
	}
	rbac.mu.Unlock()
	return
}

// Remove the role by `id`.
func (rbac *Rbac[T]) Remove(id T) (err error) {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()
	if _, ok := rbac.roles[id]; ok {
		delete(rbac.roles, id)
		for rid, parents := range rbac.parents {
			if rid == id { // delete self
				delete(rbac.parents, rid)
				continue
			}
			for parent := range parents { // delete self is other parent
				if parent == id {
					delete(rbac.parents[rid], id)
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
	if r, ok = rbac.roles[id]; ok {
		for parent := range rbac.parents[id] {
			parents = append(parents, parent)
		}
	} else {
		err = ErrRoleNotExist
	}
	return
}

// IsGranted tests if the role `id` has Permission `p` with the condition `assert`.
func (rbac *Rbac[T]) IsGranted(id T, p IPermission[T],
	assert AssertionFunc[T]) (ok bool) {
	rbac.mu.RLock()
	ok = rbac.isGranted(id, p, assert)
	rbac.mu.RUnlock()
	return
}

// IsGranted is checked role or role parent have permit this permission
func (rbac *Rbac[T]) isGranted(id T, p IPermission[T],
	assert AssertionFunc[T]) bool {
	if assert != nil && !assert(rbac, id, p) {
		return false
	}
	return rbac.recursionCheck(id, p)
}

func (rbac *Rbac[T]) recursionCheck(id T, p IPermission[T]) bool {
	if role, ok := rbac.roles[id]; ok {
		if role.Permit(p) {
			return true
		}
		if parents, ok := rbac.parents[id]; ok {
			for pID := range parents {
				if _, ok := rbac.roles[pID]; ok {
					if rbac.recursionCheck(pID, p) {
						return true
					}
				}
			}
		}
	}
	return false
}
