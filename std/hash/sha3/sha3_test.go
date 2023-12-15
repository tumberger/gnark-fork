package sha3

import (
	"crypto/rand"
	"fmt"
	"hash"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	zkhash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/sha3"
)

type testCase struct {
	zk     func(api frontend.API) (zkhash.BinaryHasher, error)
	native func() hash.Hash
}

var testCases = map[string]testCase{
	"SHA3-256": {New256, sha3.New256},
	// "SHA3-384":   {New384, sha3.New384},
	// "SHA3-512":   {New512, sha3.New512},
	// "Keccak-256": {NewLegacyKeccak256, sha3.NewLegacyKeccak256},
	// "Keccak-512": {NewLegacyKeccak512, sha3.NewLegacyKeccak512},
}

type sha3Circuit struct {
	In       []uints.U8
	Expected []uints.U8

	hasher string
}

func (c *sha3Circuit) Define(api frontend.API) error {
	newHasher, ok := testCases[c.hasher]
	if !ok {
		return fmt.Errorf("hash function unknown: %s", c.hasher)
	}
	h, err := newHasher.zk(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}

	h.Write(c.In)
	res := h.Sum()

	for i := range c.Expected {
		uapi.ByteAssertEq(c.Expected[i], res[i])
	}
	return nil
}

func TestSHA3(t *testing.T) {
	assert := test.NewAssert(t)
	in := make([]byte, 310)
	_, err := rand.Reader.Read(in)
	assert.NoError(err)

	for name := range testCases {
		assert.Run(func(assert *test.Assert) {
			name := name
			strategy := testCases[name]
			h := strategy.native()
			h.Write(in)
			expected := h.Sum(nil)

			circuit := &sha3Circuit{
				In:       make([]uints.U8, len(in)),
				Expected: make([]uints.U8, len(expected)),
				hasher:   name,
			}

			witness := &sha3Circuit{
				In:       uints.NewU8Array(in),
				Expected: uints.NewU8Array(expected),
			}

			if err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("%s: %s", name, err)
			}
		}, name)
	}
}

func TestProofComputation(t *testing.T) {

	assert := test.NewAssert(t)

	in := make([]byte, 100)
	_, err := rand.Reader.Read(in)
	assert.NoError(err)

	for name := range testCases {
		assert.Run(func(assert *test.Assert) {
			name := name
			strategy := testCases[name]
			h := strategy.native()
			h.Write(in)
			expected := h.Sum(nil)

			circuit := &sha3Circuit{
				In:       make([]uints.U8, len(in)),
				Expected: make([]uints.U8, len(expected)),
				hasher:   name,
			}
			ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)

			srs, err := test.NewKZGSRS(ccs)
			if err != nil {
				panic(err)
			}

			pk, vk, _ := plonk.Setup(ccs, srs) // WIP

			assignment := &sha3Circuit{
				In:       uints.NewU8Array(in),
				Expected: uints.NewU8Array(expected),
			}

			witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

			publicWitness, _ := witness.Public()

			proof, _ := plonk.Prove(ccs, pk, witness)
			err = plonk.Verify(proof, vk, publicWitness)
			if err != nil {
				panic(err)
			}
			// if err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField()); err != nil {
			// 	t.Fatalf("%s: %s", name, err)
			// }
		}, name)
	}

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
	// witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	// publicWitness, _ := witness.Public()

	// proof, _ := plonk.Prove(ccs, pk, witness)
	// err = plonk.Verify(proof, vk, publicWitness)
	// if err != nil {
	// 	panic(err)
	// }
}
