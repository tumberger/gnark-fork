package ecdsa

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type Signature[S emulated.FieldParams] struct {
	R, S emulated.Element[S]
}

type PublicKey[T, S emulated.FieldParams] sw_emulated.AffinePoint[T]

func (pk PublicKey[T, S]) Verify(api frontend.API, msg emulated.Element[S], sig Signature[S]) {
	cr, err := sw_emulated.New[T, S](api)
	if err != nil {
		// TODO: softer handling.
		panic(err)
	}
	scalarApi, err := emulated.NewField[S](api)
	if err != nil {
		panic(err)
	}
	baseApi, err := emulated.NewField[T](api)
	if err != nil {
		panic(err)
	}
	sInv := scalarApi.Inverse(sig.S).(emulated.Element[S])
	msInv := scalarApi.Mul(msg, sInv).(emulated.Element[S])
	rsInv := scalarApi.Mul(sig.R, sInv).(emulated.Element[S])

	qa := cr.ScalarMul(cr.Generator(), msInv)
	qb := cr.ScalarMul(sw_emulated.AffinePoint[T](pk), rsInv)
	q := cr.Add(qa, qb)
	qxBits := baseApi.ToBinary(q.X)
	qxBitsScalar := scalarApi.FromBinary(qxBits)
	scalarApi.AssertIsEqual(qxBitsScalar, sig.R)
}
