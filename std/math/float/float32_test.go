package float32

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

type Float32Circuit struct {
	// Expected Exponent & Mantissa
	ResE frontend.Variable `gnark:"x"`
	ResM frontend.Variable `gnark:"x"`

	// Values as per IEEE standard
	E1 frontend.Variable `gnark:",public"`
	M1 frontend.Variable `gnark:",public"`
	E2 frontend.Variable `gnark:",public"`
	M2 frontend.Variable `gnark:",public"`
}

type Float32MultiplyCircuit struct {
	// Expected Exponent & Mantissa
	ResE frontend.Variable `gnark:"x"`
	ResM frontend.Variable `gnark:"x"`

	FloatOne Float32
	FloatTwo Float32
}

// Define declares the circuit logic. The compiler then produces a list of constraints
// which must be satisfied (valid witness) in order to create a valid zk-SNARK
func (circuit *Float32MultiplyCircuit) Define(api frontend.API) error {

	floatAPI, err := New[Float32](api)
	if err != nil {
		return err
	}

	// Values as per IEEE standard
	// exponentBitwidth := 8
	precision := 23

	// make exponent unbiased -- TODO: move this outside of the proof and transform out of band
	circuit.FloatOne.Exponent = api.Sub(circuit.FloatOne.Exponent, 127)
	circuit.FloatTwo.Exponent = api.Sub(circuit.FloatTwo.Exponent, 127)

	// k := exponentBitwidth
	// p := precision

	floatAPI.mul(precision, circuit.FloatOne, circuit.FloatTwo)

	// circuit.FloatOne.Exponent = addition[0]
	// circuit.FloatOne.Mantissa = addition[1]

	// circuit.FloatTwo.Exponent = 3
	// circuit.FloatTwo.Mantissa = 10223616

	// multiplication := floatAPI.mul(p, circuit.FloatOne, circuit.FloatTwo)
	// e := multiplication[0]
	// m := multiplication[1]

	// // Compare results (with unbiased exponent and normalized mantissa) to inputs
	// api.AssertIsEqual(circuit.ResE, e)
	// api.AssertIsEqual(circuit.ResM, m)

	return nil
}

func TestFloat32Solving(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit Float32MultiplyCircuit

	// Inputs: 9.75 and 18.5625
	assignment := Float32MultiplyCircuit{
		FloatOne: Float32{
			Exponent: 130,
			Mantissa: 10223616,
		},
		FloatTwo: Float32{
			Exponent: 131,
			Mantissa: 9732096,
		},
		ResE: 8,
		ResM: 9045504,
	}

	assert.SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16))
}

func TestProofComputation(t *testing.T) {
	var circuit Float32MultiplyCircuit
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)

	srs, err := test.NewKZGSRS(ccs)
	if err != nil {
		panic(err)
	}

	pk, vk, _ := plonk.Setup(ccs, srs) // WIP

	assignment := Float32MultiplyCircuit{
		FloatOne: Float32{
			Exponent: 130,
			Mantissa: 10223616,
		},
		FloatTwo: Float32{
			Exponent: 131,
			Mantissa: 9732096,
		},
		ResE: 8,
		ResM: 9045504,
	}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, _ := plonk.Prove(ccs, pk, witness)
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}
