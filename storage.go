package rbac

type (
	// Storage T: service V: storge ID: storge entity ID
	Storage[T any, V any, ID comparable] interface {
		Convert(T) (V, error) // convert to model
		Save(V)               // save modle to storage
		GetBy(...ID) ([]V, error)
	}
)
