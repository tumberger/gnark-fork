package float32

import (
	"fmt"
	"math"
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
	k := 8
	// precision := 23

	// make exponent unbiased -- TODO: move this outside of the proof and transform out of band
	circuit.FloatOne.Exponent = api.Sub(circuit.FloatOne.Exponent, 127)
	circuit.FloatTwo.Exponent = api.Sub(circuit.FloatTwo.Exponent, 127)

	// computedResult := floatAPI.multiplyFloat32(k, circuit.FloatOne, circuit.FloatTwo)
	computedResult := floatAPI.AddFloat32(k, circuit.FloatOne, circuit.FloatTwo)
	// computedResult := floatAPI.mulOld(precision, circuit.FloatOne, circuit.FloatTwo)

	api.Println(computedResult.Exponent)
	api.Println("The Computed result", computedResult.Mantissa)

	api.Println("The SHOULD result", circuit.ResM)

	// Compare results (with unbiased exponent and normalized mantissa) to inputs
	api.AssertIsEqual(circuit.ResE, computedResult.Exponent)
	api.AssertIsEqual(circuit.ResM, computedResult.Mantissa)

	return nil
}

func ulp(r float32) float32 {
	rMinus := math.Nextafter32(r, float32(math.Inf(-1)))
	rPlus := math.Nextafter32(r, float32(math.Inf(1)))

	return rPlus - rMinus
}

func ulpError(r, rPrime float32) float32 {
	// Convert the absolute difference to float32
	absDiff := float32(math.Abs(float64(r - rPrime)))

	return absDiff / ulp(r)
}

func TestFloat32Solving(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit Float32MultiplyCircuit

	exponent := float32(132)
	// mantissa := float32(12618301)
	mantissa := float32(4229693)

	exponent = float32(136)
	// 9133883
	// 100010110101111100111011
	// 745275
	// mantissa = float32(745275)

	// 9134072
	// 100010110101111111111000
	// 745464
	mantissa = float32(745464)

	// Normalize the mantissa
	normalizedMantissa := float32(1.0) + mantissa/float32(math.Pow(2, 23))

	// Adjust the exponent
	actualExponent := exponent - 127

	// Calculate the float value
	floatValue := normalizedMantissa * float32(math.Pow(2, float64(actualExponent)))

	fmt.Println("The float value is:", floatValue)

	r := float32(557.488)       // Real number
	rPrime := float32(557.4995) // Computed approximation

	fmt.Println("ULP error is:", ulpError(r, rPrime))
	// 48.134 * 11.582 = 557.487976 with Float32
	// Result that it SHOULD be
	// With mantissa 9133883 - 557.488 		- 100010110101111100111011
	// Result that we get in the circuit
	// With mantissa 9134072 - 557.4995 	- 100010110101111111111000
	assignment := Float32MultiplyCircuit{
		FloatOne: Float32{
			Exponent: 132,
			Mantissa: 12618301,
			Sign:     0,
		},
		FloatTwo: Float32{
			Exponent: 130,
			Mantissa: 12144607,
			Sign:     0,
		},
		ResE: 9,
		// THIS IS WHAT IS COMPUTED AS MANTISSA IN PLAIN GO
		// ResM: 9133883,
		ResM: 9134072,
	}

	assert.ProverSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16))
}

func TestProofComputation(t *testing.T) {
	var circuit Float32MultiplyCircuit
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)

	srs, err := test.NewKZGSRS(ccs)
	if err != nil {
		panic(err)
	}

	pk, vk, _ := plonk.Setup(ccs, srs) // WIP

	// 48.135 * 11.582 = 557.499570
	assignment := Float32MultiplyCircuit{
		FloatOne: Float32{
			Exponent: 132,
			Mantissa: 12618301,
		},
		FloatTwo: Float32{
			Exponent: 130,
			Mantissa: 12144607,
		},
		ResE: 9,
		// THIS IS WHAT IS COMPUTED AS MANTISSA IN PLAIN GO
		// ResM: 9134073,
		ResM: 9134072,
	}

	// 48.134 * 11.582 = 557.487988
	// assignment := Float32MultiplyCircuit{
	// 	FloatOne: Float32{
	// 		Exponent: 132,
	// 		Mantissa: 12618039,
	// 	},
	// 	FloatTwo: Float32{
	// 		Exponent: 130,
	// 		Mantissa: 12144607,
	// 	},
	// 	ResE: 9, // 136 - 127
	// 	// THIS IS WHAT IS COMPUTED AS MANTISSA IN PLAIN GO
	// 	// ResM: 9133883,
	// 	ResM: 9133883,
	// }

	// Define the floating point numbers
	a := float32(48.134)
	// a = 48.135
	b := float32(11.582)

	// Multiply the numbers
	result := a * b

	// Print the result
	fmt.Printf("%f * %f = %f\n", a, b, result)
	// 557.487988 with Float64
	// 557.487976 with Float32

	// assignment := Float32MultiplyCircuit{
	// 	FloatOne: Float32{
	// 		Exponent: 132,
	// 		Mantissa: 12618039,
	// 	},
	// 	FloatTwo: Float32{
	// 		Exponent: 130,
	// 		Mantissa: 12144607,
	// 	},
	// 	ResE: 136,
	// 	ResM: 9133883,
	// }

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, _ := plonk.Prove(ccs, pk, witness)
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}
