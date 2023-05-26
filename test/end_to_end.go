package test

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/assert"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

const onlyGroth16Bn254 = false // TODO remove

var fr = []ecc.ID{
	ecc.BN254,
	ecc.BLS12_381,
	ecc.BLS12_377,
	ecc.BLS24_315,
	//ecc.BLS12_378, TODO: @Tabaie Not autogenerated?
	ecc.BLS24_317,
	ecc.BW6_633,
	//ecc.BW6_756, TODO: @Tabaie Not autogenerated?
	ecc.BW6_761,
}

func testPlonk(t *testing.T, assignment frontend.Circuit) {
	circuit := hollow(assignment)

	run := func(mod *big.Int) func(t *testing.T) {
		return func(t *testing.T) {
			ccs, err := frontend.Compile(mod, scs.NewBuilder, circuit)
			assert.NoError(t, err)

			witnessFull, err := frontend.NewWitness(assignment, mod)
			assert.NoError(t, err)
			witnessPublic, err := witnessFull.Public()
			assert.NoError(t, err)

			srs, err := NewKZGSRS(ccs)
			assert.NoError(t, err)

			pk, vk, err := plonk.Setup(ccs, srs)
			assert.NoError(t, err)

			proof, err := plonk.Prove(ccs, pk, witnessFull)
			assert.NoError(t, err)

			err = plonk.Verify(proof, vk, witnessPublic)
			assert.NoError(t, err)
		}
	}

	for _, id := range fr {
		t.Run(id.String(), run(id.ScalarField()))
	}
}

func testGroth16(t *testing.T, assignment frontend.Circuit) {
	circuit := hollow(assignment)
	run := func(mod *big.Int) func(*testing.T) {
		return func(t *testing.T) {
			cs, err := frontend.Compile(mod, r1cs.NewBuilder, circuit)
			assert.NoError(t, err)
			var (
				pk    groth16.ProvingKey
				vk    groth16.VerifyingKey
				w, pw witness.Witness
				proof groth16.Proof
			)
			pk, vk, err = groth16.Setup(cs)
			assert.NoError(t, err)

			w, err = frontend.NewWitness(assignment, mod)
			assert.NoError(t, err)

			proof, err = groth16.Prove(cs, pk, w)
			assert.NoError(t, err)

			pw, err = w.Public()
			assert.NoError(t, err)

			assert.NoError(t, groth16.Verify(proof, vk, pw))
		}
	}

	for _, id := range fr {
		t.Run(id.String(), run(id.ScalarField()))
	}
}

func testAll(t *testing.T, assignment frontend.Circuit) {
	t.Parallel()

	if !onlyGroth16Bn254 { // TODO remove
		t.Run("fuzzer", func(t *testing.T) {
			circuit := hollow(assignment)
			NewAssert(t).ProverSucceeded(circuit, assignment, WithBackends(backend.GROTH16, backend.PLONK)) // TODO: Support PlonkFri.Commit
		})

		t.Run("plonk-e2e", func(t *testing.T) {
			testPlonk(t, assignment)
		})
	} else {
		fr = []ecc.ID{ecc.BN254}
	}

	t.Run("groth16-e2e", func(t *testing.T) {
		testGroth16(t, assignment)
	})
}

func hollow(c frontend.Circuit) frontend.Circuit {
	cV := reflect.ValueOf(c).Elem()
	t := reflect.TypeOf(c).Elem()
	res := reflect.New(t)
	resE := res.Elem()
	resC := res.Interface().(frontend.Circuit)

	frontendVar := reflect.TypeOf((*frontend.Variable)(nil)).Elem()

	for i := 0; i < t.NumField(); i++ {
		fieldT := t.Field(i).Type
		if fieldT.Kind() == reflect.Slice && fieldT.Elem().Implements(frontendVar) {
			resE.Field(i).Set(reflect.ValueOf(make([]frontend.Variable, cV.Field(i).Len())))
		} else if fieldT != frontendVar {
			resE.Field(i).Set(cV.Field(i))
		}
	}

	return resC
}

func removePackageName(s string) string {
	return s[strings.LastIndex(s, ".")+1:]
}
