package rbac

import "sync"

type (
	// Roles is a map[id]role
	Roles[T comparable] map[T]IRole[T]

	IRole[T comparable] interface {
		ID() T
		Assign(p IPermission[T]) error // assign permission to role
		Revoke(p IPermission[T]) error // remove permission to role
		Permit(p IPermission[T]) bool
		Permissions() []IPermission[T] // get the permissions of the role
	}

	SRole[T comparable] struct {
		*sync.RWMutex `json:"-"`
		id            T              `json:"id"` // role 唯一标识
		permissions   Permissions[T] `json:"permissions"`
	}
)

func (role *SRole[T]) ID() T {
	return role.id
}
func NewRole[T comparable](id T) *SRole[T] {
	return &SRole[T]{
		RWMutex:     &sync.RWMutex{},
		id:          id,
		permissions: map[T]IPermission[T]{},
	}
}

// Assign a permission to the role.
func (role *SRole[T]) Assign(p IPermission[T]) error {
	role.Lock()
	defer role.Unlock()
	role.permissions[p.ID()] = p
	return nil
}

// Permit returns true if the role has specific permission.
func (role *SRole[T]) Permit(p IPermission[T]) bool {
	role.RLock()
	defer role.RUnlock()
	for _, rp := range role.permissions {
		if rp.Match(p) {
			return true
		}
	}
	return false
}

// Revoke the specific permission.
func (role *SRole[T]) Revoke(p IPermission[T]) error {
	role.Lock()
	defer role.Unlock()
	delete(role.permissions, p.ID())
	return nil
}

// Permissions returns all permissions into a slice.
func (role *SRole[T]) Permissions() []IPermission[T] {
	role.RLock()
	defer role.RUnlock()
	result := make([]IPermission[T], 0, len(role.permissions))
	for _, p := range role.permissions {
		result = append(result, p)
	}
	return result
}
