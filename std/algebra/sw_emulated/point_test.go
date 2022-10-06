package sw_emulated

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"

	secpCurve "github.com/consensys/gnark-crypto/ecc/secp256k1"
)

var testCurve = ecc.BN254

type NegTest[T, S emulated.FieldParams] struct {
	P, Q AffinePoint[T]
}

func (c *NegTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api)
	if err != nil {
		return err
	}
	res := cr.Neg(c.P)
	cr.AssertIsEqual(res, c.Q)
	return nil
}

func TestNeg(t *testing.T) {
	assert := test.NewAssert(t)
	_, g1GenAff := secpCurve.Generators()
	var Gy big.Int
	yn := new(big.Int).Sub(fp.Modulus(), g1GenAff.Y.ToBigIntRegular(&Gy))
	circuit := NegTest[emulated.Secp256k1, emulated.Secp256k1Scalars]{}
	witness := NegTest[emulated.Secp256k1, emulated.Secp256k1Scalars]{
		P: AffinePoint[emulated.Secp256k1]{
			X: emulated.NewElement[emulated.Secp256k1](g1GenAff.X),
			Y: emulated.NewElement[emulated.Secp256k1](g1GenAff.Y),
		},
		Q: AffinePoint[emulated.Secp256k1]{
			X: emulated.NewElement[emulated.Secp256k1](g1GenAff.X),
			Y: emulated.NewElement[emulated.Secp256k1](yn),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type AddTest[T, S emulated.FieldParams] struct {
	P, Q, R AffinePoint[T]
}

func (c *AddTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api)
	if err != nil {
		return err
	}
	res := cr.Add(c.P, c.Q)
	cr.AssertIsEqual(res, c.R)
	return nil
}

func TestAdd(t *testing.T) {
	assert := test.NewAssert(t)
	var d, a secpCurve.G1Jac
	g1GenJac, g1GenAff := secpCurve.Generators()
	d.Double(&g1GenJac)
	a.Set(&d)
	a.AddAssign(&g1GenJac)
	var dAff, aAff secpCurve.G1Affine
	dAff.FromJacobian(&d)
	aAff.FromJacobian(&a)
	circuit := AddTest[emulated.Secp256k1, emulated.Secp256k1Scalars]{}
	witness := AddTest[emulated.Secp256k1, emulated.Secp256k1Scalars]{
		P: AffinePoint[emulated.Secp256k1]{
			X: emulated.NewElement[emulated.Secp256k1](g1GenAff.X),
			Y: emulated.NewElement[emulated.Secp256k1](g1GenAff.Y),
		},
		Q: AffinePoint[emulated.Secp256k1]{
			X: emulated.NewElement[emulated.Secp256k1](dAff.X),
			Y: emulated.NewElement[emulated.Secp256k1](dAff.Y),
		},
		R: AffinePoint[emulated.Secp256k1]{
			X: emulated.NewElement[emulated.Secp256k1](aAff.X),
			Y: emulated.NewElement[emulated.Secp256k1](aAff.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type DoubleTest[T, S emulated.FieldParams] struct {
	P, Q AffinePoint[T]
}

func (c *DoubleTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api)
	if err != nil {
		return err
	}
	res := cr.Double(c.P)
	cr.AssertIsEqual(res, c.Q)
	return nil
}

func TestDouble(t *testing.T) {
	assert := test.NewAssert(t)
	var d secpCurve.G1Jac
	g1GenJac, g1GenAff := secpCurve.Generators()
	d.Double(&g1GenJac)
	var dAff secpCurve.G1Affine
	dAff.FromJacobian(&d)
	circuit := DoubleTest[emulated.Secp256k1, emulated.Secp256k1Scalars]{}
	witness := DoubleTest[emulated.Secp256k1, emulated.Secp256k1Scalars]{
		P: AffinePoint[emulated.Secp256k1]{
			X: emulated.NewElement[emulated.Secp256k1](g1GenAff.X),
			Y: emulated.NewElement[emulated.Secp256k1](g1GenAff.Y),
		},
		Q: AffinePoint[emulated.Secp256k1]{
			X: emulated.NewElement[emulated.Secp256k1](dAff.X),
			Y: emulated.NewElement[emulated.Secp256k1](dAff.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type ScalarMulTest[T, S emulated.FieldParams] struct {
	P, Q AffinePoint[T]
	S    emulated.Element[S]
}

func (c *ScalarMulTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api)
	if err != nil {
		return err
	}
	res := cr.ScalarMul(c.P, c.S)
	cr.AssertIsEqual(res, c.Q)
	return nil
}

func TestScalarMul(t *testing.T) {
	assert := test.NewAssert(t)
	s, ok := new(big.Int).SetString("44693544921776318736021182399461740191514036429448770306966433218654680512345", 10)
	assert.True(ok)
	var q secpCurve.G1Affine
	_, g1GenAff := secpCurve.Generators()
	q.ScalarMultiplication(&g1GenAff, s)

	circuit := ScalarMulTest[emulated.Secp256k1, emulated.Secp256k1Scalars]{}
	witness := ScalarMulTest[emulated.Secp256k1, emulated.Secp256k1Scalars]{
		S: emulated.NewElement[emulated.Secp256k1Scalars](s),
		P: AffinePoint[emulated.Secp256k1]{
			X: emulated.NewElement[emulated.Secp256k1](g1GenAff.X),
			Y: emulated.NewElement[emulated.Secp256k1](g1GenAff.Y),
		},
		Q: AffinePoint[emulated.Secp256k1]{
			X: emulated.NewElement[emulated.Secp256k1](q.X),
			Y: emulated.NewElement[emulated.Secp256k1](q.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
	// _, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit)
	// assert.NoError(err)
}
