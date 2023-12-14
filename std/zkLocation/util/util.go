package util

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"os/exec"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"github.com/uber/h3-go/v4"
)

const ScaleFactor = 1e9

// ToDo - Add the logic
var (
	// Mathematical constants
	Pi               frontend.Variable = 3141592653
	DoublePi         frontend.Variable = 6283185307
	HalfPi           frontend.Variable = 1570796327
	NormalizationDiv frontend.Variable = 1000000000
	MaxResolution    frontend.Variable = 15
)

// Convert scaled integer to float64 assuming the scale is 1e9
func ScaledIntToFloat64(scaledInt int) float64 {
	return float64(scaledInt) / ScaleFactor
}

// radiansToDegrees converts radians to degrees.
func RadiansToDegrees(rad float64) float64 {
	return rad * (180.0 / math.Pi)
}

func ExecuteLatLngToIJK(resolution int, latitude float64, longitude float64) (int, int, int, error) {
	// Convert float64 latitude and longitude to string
	latStr := fmt.Sprintf("%f", latitude)
	lngStr := fmt.Sprintf("%f", longitude)
	resStr := strconv.Itoa(resolution)

	// Define the path to the executable
	executablePath := "../h3-master/bin/latLngToCell"

	// Define the command and arguments using the correct path
	cmd := exec.Command(executablePath, "--resolution", resStr, "--latitude", latStr, "--longitude", lngStr)

	// Run the command and capture the output
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, 0, 0, err
	}

	// Define a regex pattern to find I, J, K values
	pattern := `I: (\d+), J: (\d+), K: (\d+)`
	re := regexp.MustCompile(pattern)

	// Find matches in the command output
	matches := re.FindStringSubmatch(string(output))
	if matches == nil || len(matches) != 4 {
		return 0, 0, 0, fmt.Errorf("failed to parse output")
	}

	// Convert matched strings to integers
	i, _ := strconv.Atoi(matches[1])
	j, _ := strconv.Atoi(matches[2])
	k, _ := strconv.Atoi(matches[3])

	return i, j, k, nil
}

// The following function translates to local IJ coordinates within the proximity of a given origin
// (not for gloabl use)
func LatLngToIJ(lat float64, lng float64, resolution int, origin h3.Cell) (I int, J int) {
	// Create a new LatLng struct
	latLng := h3.NewLatLng(lat, lng)

	// Convert LatLng to H3 cell
	cell := h3.LatLngToCell(latLng, resolution)

	// Convert H3 cell to local IJ coordinates
	coordIJ := h3.CellToLocalIJ(origin, cell)

	return coordIJ.I, coordIJ.J
}

func StrToIntSlice(inputData string, hexRepresentation bool) []int {

	// check if inputData in hex representation
	var byteSlice []byte
	if hexRepresentation {
		hexBytes, err := hex.DecodeString(inputData)
		if err != nil {
			log.Error().Msg("hex.DecodeString error.")
		}
		byteSlice = hexBytes
	} else {
		byteSlice = []byte(inputData)
	}

	// convert byte slice to int numbers which can be passed to gnark frontend.Variable
	var data []int
	for i := 0; i < len(byteSlice); i++ {
		data = append(data, int(byteSlice[i]))
	}

	return data
}

// compressThreshold --> if linear expressions are larger than this, the frontend will introduce
// intermediate constraints. The lower this number is, the faster compile time should be (to a point)
// but resulting circuit will have more constraints (slower proving time).
const compressThreshold = 100

func BenchProof(b *testing.B, circuit, assignment frontend.Circuit) {
	fmt.Println("compiling...")
	start := time.Now().UnixMicro()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(compressThreshold))
	require.NoError(b, err)
	// Print the number of constraints
	fmt.Println("Number of constraints:", cs.GetNbConstraints())
	fmt.Println("compiled in", time.Now().UnixMicro()-start, "μs")
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(b, err)
	//publicWitness := fullWitness.Public()
	fmt.Println("setting up...")
	pk, _, err := groth16.Setup(cs)
	require.NoError(b, err)

	fmt.Println("solving and proving...")
	b.ResetTimer()

	b.N = 20

	for i := 0; i < b.N; i++ {
		id := rand.Uint32() % 256 //#nosec G404 -- This is a false positive
		start = time.Now().UnixMicro()
		fmt.Println("groth16 proving", id)
		_, err = groth16.Prove(cs, pk, fullWitness)
		require.NoError(b, err)
		fmt.Println("groth16 proved", id, "in", time.Now().UnixMicro()-start, "μs")

		// fmt.Println("mimc total calls: fr=", mimcFrTotalCalls, ", snark=", mimcSnarkTotalCalls)
	}
}
