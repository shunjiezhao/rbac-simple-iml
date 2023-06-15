package rbac

import "strings"

type SPermssionLayer struct {
	SPermission[string]        // id is perrmisson
	Sep                 string // split string like /a/b/c -> a, b, c
}

func NewLayerPermission(id, sep string) SPermssionLayer {
	return SPermssionLayer{
		SPermission: NewPermission[string](id),
		Sep:         sep,
	}
}

//Match return true when we a parent perrmison or equal other
func (s SPermssionLayer) Match(other IPermission[string]) bool {
	if s.ID() == other.ID() {
		return true
	}

	q, ok := other.(SPermssionLayer)
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
