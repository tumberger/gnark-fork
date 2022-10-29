package test

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"testing"
)

type sliceCircuit struct {
	Slice [][]frontend.Variable
}

func (c *sliceCircuit) Define(api frontend.API) error {
	if len(c.Slice) != 2 {
		return fmt.Errorf("slice must have length 2")
	}

	api.AssertIsEqual(sum(api, c.Slice[0]), sum(api, c.Slice[1]))
	return nil
}

// TestInconsistentSliceLengthProving fails
func TestInconsistentSliceLengthProving(t *testing.T) {
	assignment := sliceCircuit{[][]frontend.Variable{{1, 2}, {3}}}
	circuit := sliceCircuit{[][]frontend.Variable{{nil, nil}, {nil}}}

	NewAssert(t).ProverSucceeded(&circuit, &assignment, WithBackends(backend.GROTH16), WithCurves(ecc.BN254))
}

// TestInconsistentSliceLengthSolving passes, so the problem is in the backend
func TestInconsistentSliceLengthSolving(t *testing.T) {
	assignment := sliceCircuit{[][]frontend.Variable{{1, 2}, {3}}}
	circuit := sliceCircuit{[][]frontend.Variable{{nil, nil}, {nil}}}

	NewAssert(t).SolvingSucceeded(&circuit, &assignment)
}

// TestConsistentSliceLengthProving passes, so the problem is with subslice lengths
func TestConsistentSliceLengthProving(t *testing.T) {
	assignment := sliceCircuit{[][]frontend.Variable{{1, 2}, {0, 3}}}
	circuit := sliceCircuit{[][]frontend.Variable{{nil, nil}, {nil, nil}}}

	NewAssert(t).ProverSucceeded(&circuit, &assignment)
}

// The following is not essential to this bug report and rather nitpicky

// TestCircuitAssignmentInconsistency fails as it should, but with an unhelpful error message:
// not checking if the subslices in circuit and assignment are the same length, it assumes they are
// and fails with a solving error
func TestCircuitAssignmentInconsistency(t *testing.T) {
	assignment := sliceCircuit{[][]frontend.Variable{{1, 2}, {0, 3}}}
	circuit := sliceCircuit{[][]frontend.Variable{{nil, nil}, {nil}}}

	NewAssert(t).SolvingSucceeded(&circuit, &assignment)
}

func sum(api frontend.API, slice []frontend.Variable) frontend.Variable {
	res := frontend.Variable(0)

	for i := range slice {
		res = api.Add(res, slice[i])
	}

	return res
}
