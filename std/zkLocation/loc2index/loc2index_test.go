package loc2index

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/zkLocation/util"
	"github.com/consensys/gnark/test"
)

type loc2IndexParams struct {
	Lat           int `json:"lat,string"`
	Lng           int `json:"lng,string"`
	LatIsNegative int `json:"latisneg,string"`
	LngIsNegative int `json:"lngisneg,string"`
	I             int `json:"i,string"`
	J             int `json:"j,string"`
	K             int `json:"k,string"`
	Resolution    int `json:"res,string"`
}

// Latitude: 85.94°
// Longitude: 177.62°
// Latitude: 1,500,000,000 (in radians ×109×109)
// Longitude: 3,100,000,000 (in radians ×109×109)
const loc2IndexExample = `{
    "Lat": "1500000000",
    "Lng": "3100000000",
	"latisneg": "1",
	"lngisneg": "1",
	"i": "1",
	"j": "0",
	"k": "0",
	"res": "0"
}`

// Latitude: 85.95°
// Longitude: 177.62°
// Latitude: 1,500,110,492 (in radians ×109×109)
// Longitude: 3,100,053,817 (in radians ×109×109) ​
const loc2IndexExample_MunichOne = `{
    "Lat": "1500110492",
    "Lng": "3100053817",
	"latisneg": "1",
	"lngisneg": "1",
	"i": "1",
	"j": "0",
	"k": "0",
	"res": "0"
}`

// Lat: 48.135
// Long: 11.582
// Latitude: 840,114,235 (in radians ×109×109)
// Longitude: 202,144,034 (in radians ×109×109) ​
const loc2IndexExample_MunichTwo = `{
    "Lat": "840114235",
    "Lng": "202144034",
	"latisneg": "0",
	"lngisneg": "0",
	"i": "1",
	"j": "0",
	"k": "0",
	"res": "0"
}`

// Common setup function for both tests
func setupLoc2IndexWrapper() (loc2IndexWrapper, loc2IndexWrapper) {
	var data loc2IndexParams
	err := json.Unmarshal([]byte(loc2IndexExample), &data)
	if err != nil {
		panic(err)
	}

	// Convert the scaled integers to float64 for latitude and longitude
	lat := util.ScaledIntToFloat64(data.Lat)
	if data.LatIsNegative == 1 {
		lat = -lat
	}
	lng := util.ScaledIntToFloat64(data.Lng)
	if data.LngIsNegative == 1 {
		lng = -lng
	}

	// Calculate I, J, K using the H3 library in C
	i, j, k, err := util.ExecuteLatLngToIJK(data.Resolution, util.RadiansToDegrees(lat), util.RadiansToDegrees(lng))
	if err != nil {
		panic(err)
	}

	// Update witness values with calculated I, J, K
	assignment := loc2IndexWrapper{
		Lat:           data.Lat,
		Lng:           data.Lng,
		LatIsNegative: data.LatIsNegative,
		LngIsNegative: data.LngIsNegative,
		I:             i,
		J:             j,
		K:             k,
		Resolution:    data.Resolution,
	}

	circuit := loc2IndexWrapper{
		// The circuit does not need actual values for I, J, K since these are
		// calculated within the circuit itself when running the proof or solving
		Lat:           data.Lat,
		Lng:           data.Lng,
		LatIsNegative: data.LatIsNegative,
		LngIsNegative: data.LngIsNegative,
		Resolution:    data.Resolution,
	}

	return circuit, assignment
}

const maxResolution = 14

func FuzzLoc2Index(f *testing.F) {
	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())

	f.Add(1500000000, 3099999968, 1, 0, 0) // latitude, longitude, latIsNegative, lngIsNegative, resolution
	f.Add(1500000000, 2100000000, 0, 1, 1) // Case 1
	f.Add(1500000000, 1600000000, 0, 1, 1) // Case 2
	f.Add(1500000000, 1100000000, 0, 1, 1) // Case 3
	f.Add(1500000000, 600000000, 0, 1, 1)  // Case 4
	f.Add(1500000000, 100000000, 0, 1, 1)  // Case 5
	f.Add(1500000000, 400000000, 0, 0, 1)  // Case 6
	f.Add(1500000000, 900000000, 0, 0, 1)  // Case 7
	f.Add(1500000000, 1400000000, 0, 0, 1) // Case 8
	f.Add(1500000000, 1900000000, 0, 0, 1) // Case 9
	f.Add(1500000000, 2400000000, 0, 0, 1) // Case 10
	f.Add(1500000000, 2900000000, 0, 0, 1) // Case 11
	f.Add(0, 1100000000, 0, 1, 12)         // Lat: 0, Lng: 1100000000, LatIsNegative: 0, LngIsNegative: 1, Resolution: 12
	f.Add(0, 600000000, 0, 1, 12)          // Lat: 0, Lng: 600000000, LatIsNegative: 0, LngIsNegative: 1, Resolution: 12
	f.Add(0, 100000000, 0, 1, 12)          // Lat: 0, Lng: 100000000, LatIsNegative: 0, LngIsNegative: 1, Resolution: 12
	f.Add(0, 400000000, 0, 0, 12)          // Lat: 0, Lng: 400000000, LatIsNegative: 0, LngIsNegative: 0, Resolution: 12

	f.Fuzz(func(t *testing.T, lat, lng, latIsNegative, lngIsNegative, res int) {

		/// Skip the test if latIsNegative or lngIsNegative is neither 0 nor 1
		if latIsNegative != 0 && latIsNegative != 1 {
			t.Skip("Invalid latIsNegative value, skipping fuzz test")
		}
		if lngIsNegative != 0 && lngIsNegative != 1 {
			t.Skip("Invalid lngIsNegative value, skipping fuzz test")
		}

		// Skip the test if the resolution is negative
		if res < 0 || res > maxResolution {
			t.Skip("Negative resolution, skipping fuzz test")
		}

		// If the values are valid, print all inputs
		// Print all inputs with fmt.Printf
		fmt.Printf("lat: %d, lng: %d, latIsNegative: %d, lngIsNegative: %d, resolution: %d\n",
			lat, lng, latIsNegative, lngIsNegative, res)

		// Convert the scaled integers to float64 for latitude and longitude
		latFloat := util.ScaledIntToFloat64(lat)
		if latIsNegative == 1 {
			latFloat = -latFloat
		}
		lngFloat := util.ScaledIntToFloat64(lng)
		if lngIsNegative == 1 {
			lngFloat = -lngFloat
		}

		// Print the values
		fmt.Printf("resolution: %d, latFloat: %f, lngFloat: %f\n", res, latFloat, lngFloat)

		// Convert radians to degrees and check their ranges
		latDegrees := util.RadiansToDegrees(latFloat)
		lngDegrees := util.RadiansToDegrees(lngFloat)
		if latDegrees < -90 || latDegrees > 90 {
			t.Skip("Latitude out of valid degree range")
		}
		if lngDegrees < -180 || lngDegrees > 180 {
			t.Skip("Longitude out of valid degree range")
		}

		fmt.Printf("resolution: %d, latFloat: %f, lngFloat: %f\n", res, latDegrees, lngDegrees)

		// Calculate I, J, K using the H3 library in C
		i, j, k, _ := util.ExecuteLatLngToIJK(res, latDegrees, lngDegrees)
		// if err != nil {
		// 	t.Fatalf("Failed to calculate IJK: %v", err)
		// }

		// Print the calculated I, J, K values
		fmt.Printf("i: %d, j: %d, k: %d\n", i, j, k)

		// Update witness values with calculated I, J, K
		assignment := loc2IndexWrapper{
			Lat:           lat,
			Lng:           lng,
			LatIsNegative: latIsNegative,
			LngIsNegative: lngIsNegative,
			I:             i,
			J:             j,
			K:             k,
			Resolution:    res,
		}

		circuit := loc2IndexWrapper{
			// The circuit does not need actual values for I, J, K since these are
			// calculated within the circuit itself when running the proof or solving
			Lat:           lat,
			Lng:           lng,
			LatIsNegative: latIsNegative,
			LngIsNegative: lngIsNegative,
			Resolution:    res,
		}

		// Perform assertions using the assert object from the 'test' package
		assert := test.NewAssert(t)
		assert.ProverSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
		// You can add more assertions as necessary
	})
}

func TestLoc2IndexSolving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupLoc2IndexWrapper()

	// Solve the circuit and assert.
	assert.SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16))
}

func TestLoc2IndexProving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupLoc2IndexWrapper()

	// Proof successfully generated
	assert.ProverSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16))
}

func TestProofComputationPlonk(t *testing.T) {

	circuit, assignment := setupLoc2IndexWrapper()
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)

	srs, err := test.NewKZGSRS(ccs)
	if err != nil {
		panic(err)
	}

	pk, vk, _ := plonk.Setup(ccs, srs) // WIP

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
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, _ := plonk.Prove(ccs, pk, witness)
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}

func TestProofComputationPlonkBLS(t *testing.T) {

	circuit, assignment := setupLoc2IndexWrapper()
	ccs, _ := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)

	srs, err := test.NewKZGSRS(ccs)
	if err != nil {
		panic(err)
	}

	pk, vk, _ := plonk.Setup(ccs, srs) // WIP

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
	witness, _ := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
	publicWitness, _ := witness.Public()

	proof, _ := plonk.Prove(ccs, pk, witness)
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}

func TestProofComputationGroth(t *testing.T) {

	circuit, assignment := setupLoc2IndexWrapper()
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// srs, err := test.NewKZGSRS(ccs)
	pk, vk, err := groth16.Setup(ccs) // WIP
	if err != nil {
		panic(err)
	}

	// pk, vk, _ := plonk.Setup(ccs, srs) // WIP

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
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, _ := groth16.Prove(ccs, pk, witness)
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}

func BenchmarkLoc2IndexProof(b *testing.B) {
	circuit, assignment := setupLoc2IndexWrapper()
	util.BenchProof(b, &circuit, &assignment)
}
