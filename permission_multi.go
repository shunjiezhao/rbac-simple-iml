package rbac

import "strings"

type SPermissionLayer struct {
	IPermission[string] `json:"Ipermission"` // id is perrmisson
	Sep                 string               `json:"sep"       ` // split string like /a/b/c -> a, b, c
}

func NewLayerPermission(id, sep string) SPermissionLayer {
	return SPermissionLayer{
		IPermission: NewPermission[string](id),
		Sep:         sep,
	}
}

// Match return true when we a parent perrmison or equal other
func (s SPermissionLayer) Match(other IPermission[string]) bool {
	if s.ID() == other.ID() {
		return true
	}

	q, ok := other.(SPermissionLayer)
	if !ok {
		return false // type not equal
	}

	pPer := strings.Split(s.ID(), s.Sep)
	qPer := strings.Split(q.ID(), q.Sep)

	if len(pPer) > len(qPer) {
		return false
	}

	for k, v := range pPer {
		if v != qPer[k] {
			return false
		}
	}
	return true
}
