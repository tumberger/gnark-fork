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

// Package eddsa provides a ZKP-circuit function to verify a EdDSA signature.
package eddsa

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

// PublicKey stores an eddsa public key (to be used in gnark circuit)
type PublicKey struct {
	A     twistededwards.Point
	Curve twistededwards.EdCurve
}

// Signature stores a signature  (to be used in gnark circuit)
// An EdDSA signature is a tuple (R,S) where R is a point on the twisted Edwards curve
// and S a scalar. Since the base field of the twisted Edwards is Fr, the number of points
// N on the Edwards is < r+1+2sqrt(r)+2 (since the curve has 2 points of multiplicity 2).
// The subgroup l used in eddsa is <1/2N, so the reduction
// mod l ensures S < r, therefore there is no risk of overflow.
type Signature struct {
	R twistededwards.Point
	S frontend.Variable
}

// Verify verifies an eddsa signature
// cf https://en.wikipedia.org/wiki/EdDSA
func Verify(api frontend.API, sig Signature, msg frontend.Variable, pubKey PublicKey) error {

	// compute H(R, A, M), all parameters in data are in Montgomery form
	data := []frontend.Variable{
		sig.R.X,
		sig.R.Y,
		pubKey.A.X,
		pubKey.A.Y,
		msg,
	}

	hash, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hash.Write(data...)
	hramConstant := hash.Sum()

	base := twistededwards.Point{}
	base.X = pubKey.Curve.Base.X
	base.Y = pubKey.Curve.Base.Y

	// lhs = [S]G
	cofactor := pubKey.Curve.Cofactor.Uint64()
	lhs := twistededwards.Point{}
	lhs.ScalarMul(api, &base, sig.S, pubKey.Curve)

	// rhs = R+[H(R,A,M)]*A
	rhs := twistededwards.Point{}
	rhs.ScalarMul(api, &pubKey.A, hramConstant, pubKey.Curve).
		Add(api, &rhs, &sig.R, pubKey.Curve)
	rhs.MustBeOnCurve(api, pubKey.Curve)

	// lhs-rhs
	rhs.Neg(api, &rhs).Add(api, &lhs, &rhs, pubKey.Curve)

	// [cofactor]*(lhs-rhs)
	switch cofactor {
	case 4:
		rhs.Double(api, &rhs, pubKey.Curve).
			Double(api, &rhs, pubKey.Curve)
	case 8:
		rhs.Double(api, &rhs, pubKey.Curve).
			Double(api, &rhs, pubKey.Curve).Double(api, &rhs, pubKey.Curve)
	}

	api.AssertIsEqual(rhs.X, lhs.X)
	api.AssertIsEqual(rhs.Y, lhs.Y)

	return nil
}
