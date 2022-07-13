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
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// GAffine point in affine coords
type GAffine struct {
	X, Y frontend.Variable
}

// Neg outputs -p
func (p *GAffine) Neg(api frontend.API, p1 GAffine) *GAffine {
	p.X = p1.X
	p.Y = api.Neg(p1.Y)
	return p
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (p *GAffine) AssertIsEqual(api frontend.API, other GAffine) {
	api.AssertIsEqual(p.X, other.X)
	api.AssertIsEqual(p.Y, other.Y)
}

// AddAssign adds p1 to p using the affine formulas with division, and return p
func (p *GAffine) Add(api frontend.API, q, r GAffine) *GAffine {

	// compute lambda = (p1.y-p.y)/(p1.x-p.x)
	lambda := api.DivUnchecked(api.Sub(r.Y, q.Y), api.Sub(r.X, q.X))

	// xr = lambda**2-p.x-p1.x
	xr := api.Sub(api.Mul(lambda, lambda), api.Add(q.X, r.X))

	// p.y = lambda(p.x-xr) - p.y
	p.Y = api.Sub(api.Mul(lambda, api.Sub(q.X, xr)), q.Y)

	//p.x = xr
	p.X = xr

	return p
}

// Double double a point in affine coords
func (p *GAffine) Double(api frontend.API, p1 GAffine) *GAffine {

	var three, two big.Int
	three.SetInt64(3)
	two.SetInt64(2)

	// compute lambda = (3*p1.x**2+a)/2*p1.y, here we assume a=0 (j invariant 0 curve)
	lambda := api.DivUnchecked(api.Mul(p1.X, p1.X, three), api.Mul(p1.Y, two))

	// xr = lambda**2-p1.x-p1.x
	xr := api.Sub(api.Mul(lambda, lambda), api.Mul(p1.X, two))

	// p.y = lambda(p.x-xr) - p.y
	p.Y = api.Sub(api.Mul(lambda, api.Sub(p1.X, xr)), p1.Y)

	//p.x = xr
	p.X = xr

	return p
}

func (p *GAffine) ScalarMulBits(api frontend.API, p1 GAffine, sBits []frontend.Variable) *GAffine {

	// the result is set to p1 to avoid incomplete formulas
	var res, acc, tmp GAffine
	res = p1
	acc.Double(api, p1)

	// right to left expo, with LSB assumed to be 1 for the moment.
	// p1 is subtracted at the end if the LSB was 0.
	for i := 1; i < len(sBits); i++ {
		tmp.Add(api, res, acc)
		res.X = api.Select(sBits[i], tmp.X, res.X)
		res.Y = api.Select(sBits[i], tmp.Y, res.Y)
		acc.Double(api, acc)
	}

	// check if the LSB was 0, if so, we substract p1 from the result.
	tmp.Neg(api, p1)
	tmp.Add(api, res, tmp)
	res.X = api.Select(sBits[0], tmp.X, res.X)
	res.Y = api.Select(sBits[0], tmp.Y, res.Y)

	// return res
	return &res

}

func (p *GAffine) ScalarMul(api frontend.API, p1 GAffine, s frontend.Variable) *GAffine {
	sBits := api.ToBinary(s, 256)
	return p.ScalarMulBits(api, p1, sBits)
}
