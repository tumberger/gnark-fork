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

package mimc

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

type mimcCircuit struct {
	ExpectedResult frontend.Variable `gnark:"data,public"`
	Data           [10]frontend.Variable
}

func (circuit *mimcCircuit) Define(api frontend.API) error {
	mimc, err := NewMiMC(api)
	if err != nil {
		return err
	}
	mimc.Write(circuit.Data[:]...)
	result := mimc.Sum()
	api.AssertIsEqual(result, circuit.ExpectedResult)
	return nil
}

func TestMimcAll(t *testing.T) {
	assert := test.NewAssert(t)

	curves := map[ecc.ID]hash.Hash{
		ecc.BN254:     hash.MIMC_BN254,
		ecc.BLS12_381: hash.MIMC_BLS12_381,
		ecc.BLS12_377: hash.MIMC_BLS12_377,
		ecc.BW6_761:   hash.MIMC_BW6_761,
		ecc.BW6_633:   hash.MIMC_BW6_633,
		ecc.BLS24_315: hash.MIMC_BLS24_315,
		ecc.BLS24_317: hash.MIMC_BLS24_317,
	}

	for curve, hashFunc := range curves {

		// minimal cs res = hash(data)
		var circuit, validWitness, invalidWitness mimcCircuit

		modulus := curve.ScalarField()
		var data [10]big.Int
		data[0].Sub(modulus, big.NewInt(1))
		for i := 1; i < 10; i++ {
			data[i].Add(&data[i-1], &data[i-1]).Mod(&data[i], modulus)
		}

		// running MiMC (Go)
		goMimc := hashFunc.New()
		for i := 0; i < 10; i++ {
			goMimc.Write(data[i].Bytes())
		}
		expectedh := goMimc.Sum(nil)

		// assert correctness against correct witness
		for i := 0; i < 10; i++ {
			validWitness.Data[i] = data[i].String()
		}
		validWitness.ExpectedResult = expectedh

		// assert failure against wrong witness
		for i := 0; i < 10; i++ {
			invalidWitness.Data[i] = data[i].Sub(&data[i], big.NewInt(1)).String()
		}
		invalidWitness.ExpectedResult = expectedh

		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithInvalidAssignment(&invalidWitness),
			test.WithCurves(curve))
	}

}

func TestProofComputation(t *testing.T) {
	var circuit, validWitness mimcCircuit
	ccs, _ := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)

	srs, err := test.NewKZGSRS(ccs)
	if err != nil {
		panic(err)
	}

	pk, vk, _ := plonk.Setup(ccs, srs) // WIP

	modulus := ecc.BLS12_381.ScalarField()
	var data [10]big.Int
	data[0].Sub(modulus, big.NewInt(1))
	for i := 1; i < 10; i++ {
		data[i].Add(&data[i-1], &data[i-1]).Mod(&data[i], modulus)
	}

	// running MiMC (Go)
	goMimc := hash.MIMC_BLS12_381.New()
	for i := 0; i < 10; i++ {
		goMimc.Write(data[i].Bytes())
	}
	expectedh := goMimc.Sum(nil)

	// assert correctness against correct witness
	for i := 0; i < 10; i++ {
		validWitness.Data[i] = data[i].String()
	}
	validWitness.ExpectedResult = expectedh

	// assignment := Float32MultiplyCircuit{
	// 	FloatOne: Float32{
	// 		Exponent: 130,
	// 		Mantissa: 10223616,
	// 	},
	// 	FloatTwo: Float32{
	// 		Exponent: 131,
	// 		Mantissa: 9732096,
	// 	},
	// 	ResE: 8,
	// 	ResM: 9045504,
	// }
	witness, _ := frontend.NewWitness(&validWitness, ecc.BLS12_381.ScalarField())
	publicWitness, _ := witness.Public()

	proof, _ := plonk.Prove(ccs, pk, witness)
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}
