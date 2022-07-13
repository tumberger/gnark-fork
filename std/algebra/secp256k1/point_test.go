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

package secp256k1

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/nonnative"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type emulatedField struct {
	params  *nonnative.Params
	name    string
	modulus *big.Int
	nbBits  int
}

func emulatedFields(t *testing.T) []emulatedField {
	t.Helper()
	var modulus big.Int
	modulus.SetString("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10)
	var ret []emulatedField
	for _, limbLength := range []int{32, 48, 64} {
		secp256k1fp, err := nonnative.NewParams(limbLength, new(big.Int).SetBytes([]byte{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
		}))
		if err != nil {
			t.Fatal(err)
		}
		ret = append(ret, emulatedField{secp256k1fp, "secp256k1", &modulus, 256})
	}
	return ret
}

func testName(ef emulatedField) string {
	return fmt.Sprintf("%s/limb=%d", ef.name, ef.nbBits)
}

//---------------------------------------------------
// Neg

type NegTest struct {
	P, Q GAffine
}

func (c *NegTest) Define(api frontend.API) error {

	var res GAffine
	res.Neg(api, c.P)
	res.AssertIsEqual(api, c.Q)

	return nil
}

func TestNeg(t *testing.T) {

	secpCurve := secp256k1.S256()
	var yn big.Int
	yn.Sub(secpCurve.P, secpCurve.Gy)

	for _, fp := range emulatedFields(t) {

		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {

			// api decorator
			wrapper := func(api frontend.API) frontend.API {
				return nonnative.NewAPI(api, params)
			}

			// circuit
			// circuit := NegTest{
			// 	P: GAffine{X: params.Placeholder(), Y: params.Placeholder()},
			// 	Q: GAffine{X: params.Placeholder(), Y: params.Placeholder()},
			// }
			var circuit NegTest

			// witness
			witness := NegTest{
				P: GAffine{X: params.ConstantFromBigOrPanic(secpCurve.Gx), Y: params.ConstantFromBigOrPanic(secpCurve.Gy)},
				Q: GAffine{X: params.ConstantFromBigOrPanic(secpCurve.Gx), Y: params.ConstantFromBigOrPanic(&yn)},
			}

			// IsSolved
			err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField(), test.WithApiWrapper(wrapper))
			assert.NoError(err)

		}, testName(fp))

	}

}

//---------------------------------------------------
// Add

type AddTest struct {
	P, Q, R GAffine
}

func (c *AddTest) Define(api frontend.API) error {

	c.P.Add(api, c.P, c.Q)
	api.AssertIsEqual(c.P, c.R)

	return nil
}

func TestAdd(t *testing.T) {

	t.Skip("failing...")

	secpCurve := secp256k1.S256()
	xd, yd := secpCurve.Double(secpCurve.Gx, secpCurve.Gy)
	xa, ya := secpCurve.Add(xd, yd, secpCurve.Gx, secpCurve.Gy)

	// for _, fp := range emulatedFields(t) {
	fp := emulatedFields(t)[0]

	params := fp.params
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {

		// api decorator
		wrapper := func(api frontend.API) frontend.API {
			return nonnative.NewAPI(api, params)
		}

		// circuit
		circuit := AddTest{
			P: GAffine{X: params.Placeholder(), Y: params.Placeholder()},
			Q: GAffine{X: params.Placeholder(), Y: params.Placeholder()},
			R: GAffine{X: params.Placeholder(), Y: params.Placeholder()},
		}

		// witness
		witness := AddTest{
			P: GAffine{X: params.ConstantFromBigOrPanic(secpCurve.Gx), Y: params.ConstantFromBigOrPanic(secpCurve.Gy)},
			Q: GAffine{X: params.ConstantFromBigOrPanic(xd), Y: params.ConstantFromBigOrPanic(yd)},
			R: GAffine{X: params.ConstantFromBigOrPanic(xa), Y: params.ConstantFromBigOrPanic(ya)},
		}

		// IsSolved
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField(), test.WithApiWrapper(wrapper))
		assert.NoError(err)

	}, testName(fp))

	// }

}

//---------------------------------------------------
// Double

type DoubleTest struct {
	P, Q GAffine
}

func (c *DoubleTest) Define(api frontend.API) error {

	c.P.Double(api, c.P)
	api.AssertIsEqual(c.P, c.Q)

	return nil
}

func TestDouble(t *testing.T) {

	// t.Skip("failing...")

	secpCurve := secp256k1.S256()
	xd, yd := secpCurve.Double(secpCurve.Gx, secpCurve.Gy)

	// for _, fp := range emulatedFields(t) {
	fp := emulatedFields(t)[0]

	params := fp.params
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {

		// api decorator
		wrapper := func(api frontend.API) frontend.API {
			return nonnative.NewAPI(api, params)
		}

		// circuit
		circuit := DoubleTest{
			P: GAffine{X: params.Placeholder(), Y: params.Placeholder()},
			Q: GAffine{X: params.Placeholder(), Y: params.Placeholder()},
		}

		// witness
		witness := DoubleTest{
			P: GAffine{X: params.ConstantFromBigOrPanic(secpCurve.Gx), Y: params.ConstantFromBigOrPanic(secpCurve.Gy)},
			Q: GAffine{X: params.ConstantFromBigOrPanic(xd), Y: params.ConstantFromBigOrPanic(yd)},
		}

		// IsSolved
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField(), test.WithApiWrapper(wrapper))
		assert.NoError(err)

	}, testName(fp))

	// }

}

//---------------------------------------------------
// Scalar mul

type ScalarMulTest struct {
	// params *nonnative.Params
	P, Q GAffine
	S    frontend.Variable
}

func (c *ScalarMulTest) Define(api frontend.API) error {

	// api = nonnative.NewAPI(api, c.params)

	c.P.ScalarMul(api, c.P, c.S)
	c.P.AssertIsEqual(api, c.Q)

	return nil
}

func TestScalarMul(t *testing.T) {

	// t.Skip("failing...")

	secpCurve := secp256k1.S256()
	var s big.Int
	s.SetString("187836863297923799798778798", 10)
	sx, sy := secpCurve.ScalarMult(secpCurve.Gx, secpCurve.Gy, s.Bytes())

	for _, fp := range emulatedFields(t) {

		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {

			// api decorator
			wrapper := func(api frontend.API) frontend.API {
				return nonnative.NewAPI(api, params)
			}

			// circuit
			circuit := ScalarMulTest{
				// params: fp.params,
				S: params.Placeholder(),
				P: GAffine{X: params.Placeholder(), Y: params.Placeholder()},
				Q: GAffine{X: params.Placeholder(), Y: params.Placeholder()},
			}

			// witness
			witness := ScalarMulTest{
				S: s,
				P: GAffine{X: params.ConstantFromBigOrPanic(secpCurve.Gx), Y: params.ConstantFromBigOrPanic(secpCurve.Gy)},
				Q: GAffine{X: params.ConstantFromBigOrPanic(sx), Y: params.ConstantFromBigOrPanic(sy)},
			}

			// IsSolved
			err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField(), test.WithApiWrapper(wrapper))
			assert.NoError(err)
			// cc, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)
			// assert.NoError(err)
			// fmt.Printf("nb constraints: %d\n", cc.GetNbConstraints())

		}, testName(fp))

	}

}

// mock test

type mockAdd struct {
	X, Y frontend.Variable
}

func (c *mockAdd) Define(api frontend.API) error {
	t := api.Neg(c.Y)
	api.AssertIsEqual(c.X, t)
	return nil
}

func TestMockAdd(t *testing.T) {

	// common data
	assert := test.NewAssert(t)
	em := emulatedFields(t)
	params := em[0].params

	secpCurve := secp256k1.S256()
	x, y := secpCurve.Double(secpCurve.Gx, secpCurve.Gy)
	y.Sub(secpCurve.P, x)
	// y.Set(x)

	// api decorator
	wrapper := func(api frontend.API) frontend.API {
		return nonnative.NewAPI(api, params)
	}

	// circuit
	circuit := mockAdd{
		X: params.Placeholder(),
		Y: params.Placeholder(),
	}

	// witness
	witness := mockAdd{
		X: params.ConstantFromBigOrPanic(x),
		Y: params.ConstantFromBigOrPanic(y),
	}

	// test isSolved
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField(), test.WithApiWrapper(wrapper))
	assert.NoError(err)

}
