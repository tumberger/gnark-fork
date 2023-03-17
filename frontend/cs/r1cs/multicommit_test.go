package r1cs_test

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type LazyCommitmentsCircuit struct {
	X1, X2 frontend.Variable
	Res    frontend.Variable `gnark:",public"`
}

func (c *LazyCommitmentsCircuit) Define(api frontend.API) error {
	mcapi, ok := api.Compiler().(frontend.MultiCommitter)
	if !ok {
		return fmt.Errorf("not multicommitter")
	}
	c1 := mcapi.MultiCommit(c.X1)
	c2 := mcapi.MultiCommit(c.X2)
	res := api.Mul(api.Sub(c1, c.X1), api.Sub(c2, c.X2))
	api.AssertIsDifferent(res, 0)
	api.Mul(c.X1, c.X2)
	return nil
}

func TestLazyCommitmentCircuit(t *testing.T) {
	circuit := &LazyCommitmentsCircuit{}
	assignment := &LazyCommitmentsCircuit{
		X1:  2,
		X2:  3,
		Res: 6,
	}
	assert := test.NewAssert(t)
	err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(err)
	_ccs, ok := ccs.(*cs.R1CS)
	assert.True(ok)
	constraints, r := _ccs.GetConstraints()
	for _, c := range constraints {
		t.Log(c.String(r))
	}
	// witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	// assert.NoError(err)
	// sol, err := ccs.Solve(witness)
	// assert.NoError(err)
	// pk, vk, err := groth16.Setup(ccs)
	// assert.NoError(err)
	// proof, err := groth16.Prove(ccs, pk, witness)
	// assert.NoError(err)
	// _ = proof
	// _ = vk
	// _ = sol
}
