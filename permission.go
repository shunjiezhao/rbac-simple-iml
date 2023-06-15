package rbac

type (
	IPermission[T comparable] interface {
		ID() T
		Match(IPermission[T]) bool // ==
	}

	// Perrmissions is a map[id]Permission
	Permissions[T comparable] map[T]IPermission[T]
)

func NewPermission[T comparable](id T) IPermission[T] {
	return SPermission[T]{
		id: id,
	}
}

type SPermission[T comparable] struct {
	id T `json:"id"`
}

func (p SPermission[T]) ID() T {
	return p.id
}

func (p SPermission[T]) Match(other IPermission[T]) bool {
	return p.ID() == other.ID()
}
