package rbac

type (
	// Storage T: service V: storage ID: storage entity ID
	Storage[T any, V any, ID comparable] interface {
		Convert(T) (V, error) // convert to model
		Save(V)               // save module to storage
		GetBy(...ID) ([]V, error)
	}
)
