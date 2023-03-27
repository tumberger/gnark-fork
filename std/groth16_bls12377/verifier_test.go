/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package groth16_bls12377

import (
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
	groth16_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/groth16"
)

const (
	preImage   = "4992816046196248432836492760315135318126925090839638585255611512962528270024"
	publicHash = "7831393781387060555412927989411398077996792073838215843928284475008119358174"
)

type mimcCircuit struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

func (circuit *mimcCircuit) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	mimc.Write(circuit.PreImage)
	api.AssertIsEqual(mimc.Sum(), circuit.Hash)
	return nil
}

// Calculate the expected output of MIMC through plain invocation
func preComputeMimc(preImage frontend.Variable) interface{} {
	var expectedY fr.Element
	expectedY.SetInterface(preImage)
	// calc MiMC
	goMimc := hash.MIMC_BLS12_377.New()
	goMimc.Write(expectedY.Marshal())
	expectedh := goMimc.Sum(nil)
	return expectedh
}

type verifierCircuit struct {
	InnerProof Proof
	InnerVk    VerifyingKey
	Hash       frontend.Variable
}

func (circuit *verifierCircuit) Define(api frontend.API) error {
	// create the verifier cs
	Verify(api, circuit.InnerVk, circuit.InnerProof, []frontend.Variable{circuit.Hash})

	return nil
}
func TestVerifier(t *testing.T) {
	// get the data
	var innerVk groth16_bls12377.VerifyingKey
	var innerProof groth16_bls12377.Proof

	// create a mock cs: knowing the preimage of a hash using mimc
	var c mimcCircuit
	r1cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		t.Fatal(err)
	}

	// build the witness
	var pre_assignment mimcCircuit
	pre_assignment.PreImage = preImage
	pre_assignment.Hash = publicHash
	pre_witness, err := frontend.NewWitness(&pre_assignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	GenerateBls12377InnerProof(&innerVk, &innerProof, pre_witness, r1cs)

	// create an empty cs
	var circuit verifierCircuit
	circuit.InnerVk.G1.K = make([]sw_bls12377.G1Affine, len(innerVk.G1.K))

	// create assignment, the private part consists of the proof,
	// the public part is exactly the public part of the inner proof,
	// up to the renaming of the inner ONE_WIRE to not conflict with the one wire of the outer proof.
	var witness verifierCircuit
	witness.InnerProof.Ar.Assign(&innerProof.Ar)
	witness.InnerProof.Krs.Assign(&innerProof.Krs)
	witness.InnerProof.Bs.Assign(&innerProof.Bs)
	witness.InnerVk.Assign(&innerVk)

	var assignment mimcCircuit
	assignment.PreImage = preImage
	witness.Hash = preComputeMimc(assignment.PreImage)

	// verifies the cs
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&circuit, &verifierCircuit{
		InnerProof: witness.InnerProof,
		InnerVk:    witness.InnerVk,
		Hash:       witness.Hash,
	}, test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16))
}

func BenchmarkCompile(b *testing.B) {
	// get the data
	var innerVk groth16_bls12377.VerifyingKey
	var innerProof groth16_bls12377.Proof

	// create a mock cs: knowing the preimage of a hash using mimc
	var c mimcCircuit
	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		b.Fatal(err)
	}

	// build the witness
	var pre_assignment mimcCircuit
	pre_assignment.PreImage = preImage
	pre_assignment.Hash = publicHash
	pre_witness, err := frontend.NewWitness(&pre_assignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		b.Fatal(err)
	}

	GenerateBls12377InnerProof(&innerVk, &innerProof, pre_witness, cs)

	// create an empty cs
	var circuit verifierCircuit
	circuit.InnerVk.G1.K = make([]sw_bls12377.G1Affine, len(innerVk.G1.K))

	var ccs constraint.ConstraintSystem
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ccs, err = frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.Log(ccs.GetNbConstraints())
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
}
