package rbac

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func pestPrepareCircleData(t *testing.T) {
	rbac = New[string]()
	assert.Nil(t, rA.Assign(pA))
	assert.Nil(t, rB.Assign(pB))
	assert.Nil(t, rC.Assign(pC))
	assert.Nil(t, rA.Assign(pAll))
	assert.Nil(t, rB.Assign(pAll))
	assert.Nil(t, rC.Assign(pAll))
	assert.Nil(t, rbac.Add(rA))
	assert.Nil(t, rbac.Add(rB))
	assert.Nil(t, rbac.Add(rC))
}

func TestCheckExtendCircleCircle(t *testing.T) {
	pestPrepareCircleData(t)
	t.Run("have circle", func(t *testing.T) {
		assert.Nil(t, rbac.SetParents(rA, rB))
		assert.Nil(t, rbac.SetParents(rB, rC))
		assert.Nil(t, rbac.SetParents(rC, rA))
		assert.Error(t, CheckExtendCircle(rbac))
	})
	t.Run("not have circle", func(t *testing.T) {
		assert.Nil(t, rbac.RemoveParent(rC.ID(), rA.ID()))
		assert.Nil(t, CheckExtendCircle(rbac))
	})
}

func TestAllGranted(t *testing.T) {
	pestPrepareCircleData(t)
	// All roles have pAll
	roles := []string{"role-a", "role-b", "role-c"}
	if !AllGranted(rbac, roles, pAll) {
		t.Errorf("All roles(%v) were expected having %s, but they weren't.", roles, pAll)
	}

	if AllGranted(rbac, roles, pA) {
		t.Errorf("Not all roles(%v) were expected having %s, but they were.", roles, pA)
	}
}

func TestAnyGranted(t *testing.T) {
	pestPrepareCircleData(t)
	// All roles have pAll
	roles := []string{"role-a", "role-b", "role-c"}
	if !AnyGranted(rbac, roles, pA) {
		t.Errorf("All roles(%v) were expected having %s, but they weren't.", roles, pAll)
	}

	if AnyGranted(rbac, roles, pNone) {
		t.Errorf("Not all roles(%v) were expected having %s, but they were.", roles, pA)
	}
}
