package sha2

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type sha2Circuit struct {
	In       []uints.U8
	Expected [32]uints.U8
}

func (c *sha2Circuit) Define(api frontend.API) error {
	h, err := New(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	h.Write(c.In)
	res := h.Sum()
	if len(res) != 32 {
		return fmt.Errorf("not 32 bytes")
	}
	for i := range c.Expected {
		uapi.ByteAssertEq(c.Expected[i], res[i])
	}
	return nil
}

func TestSHA2(t *testing.T) {
	bts := make([]byte, 310)
	dgst := sha256.Sum256(bts)
	witness := sha2Circuit{
		In: uints.NewU8Array(bts),
	}
	copy(witness.Expected[:], uints.NewU8Array(dgst[:]))
	err := test.IsSolved(&sha2Circuit{In: make([]uints.U8, len(bts))}, &witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
}

func TestProofComputation(t *testing.T) {
	var circuit sha2Circuit
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)

	srs, err := test.NewKZGSRS(ccs)
	if err != nil {
		panic(err)
	}

	pk, vk, _ := plonk.Setup(ccs, srs) // WIP

	bts := make([]byte, 310)
	dgst := sha256.Sum256(bts)
	assignment := sha2Circuit{
		In: uints.NewU8Array(bts),
	}
	copy(assignment.Expected[:], uints.NewU8Array(dgst[:]))

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
