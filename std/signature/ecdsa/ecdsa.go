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

package ecdsa

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/secp256k1"
	"github.com/consensys/gnark/std/math/nonnative"
)

// Ecdsa signature
// The R, S are variables in Fr, the group of the elliptic curve.
type Sig struct {
	R, S, M nonnative.Element
}

// Public ECDSA key.
// Its coordinates are in Fp, the field of definition of the elliptic curve.
type PublicKey = secp256k1.GAffine

// VerifySignature
// sig signature
// pub public key
// m message
// apiR, apiP respectevely the api for the curve group and field of definition
func VerifySignature(sig Sig, pub PublicKey, G secp256k1.GAffine, apiR, apiP frontend.API) {

	// S**-1*m, S**-1*R
	sInv := apiR.Inverse(sig.S)
	msInv := apiR.Mul(sig.M, sInv)
	rsInv := apiR.Mul(sig.R, sInv)

	// [S**-1*m]G + [S**-1*R]pub
	msInvBits := apiR.ToBinary(msInv, 256)
	rsInvBits := apiR.ToBinary(rsInv, 256)
	var qa, qb secp256k1.GAffine
	qa.ScalarMulBits(apiP, G, msInvBits)
	qb.ScalarMulBits(apiP, pub, rsInvBits)
	qa.Add(apiP, qa, qb)

	// check that X([S**-1*m]G + [S**-1*R]pub)=R
	rbin := apiR.ToBinary(sig.R)
	rp := apiP.FromBinary(rbin)
	apiP.AssertIsEqual(rp, qa.X)

}
