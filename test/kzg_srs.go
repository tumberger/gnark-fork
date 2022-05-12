/*
Copyright © 2021 ConsenSys Software Inc.

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

package test

import (
	"crypto/rand"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/frontend"

	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	kzg_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/kzg"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	kzg_bw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr/kzg"
	kzg_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/kzg"
)

const srsCachedSize = (1 << 14) + 3

// NewKZGSRS uses ccs nb variables and nb constraints to initialize a kzg srs
// for sizes < 2¹⁵, returns a pre-computed cached SRS
//
// /!\ warning /!\: this method is here for convenience only: in production, a SRS generated through MPC should be used.
func NewKZGSRS(ccs frontend.CompiledConstraintSystem) (kzg.SRS, error) {

	nbConstraints := ccs.GetNbConstraints()
	_, _, public := ccs.GetNbVariables()
	sizeSystem := nbConstraints + public
	kzgSize := ecc.NextPowerOfTwo(uint64(sizeSystem)) + 3

	if kzgSize <= srsCachedSize {
		return getCachedSRS(ccs)
	}

	return newKZGSRS(ccs.Modulus(), kzgSize)

}

var srsCache map[string]kzg.SRS
var lock sync.Mutex

func init() {
	srsCache = make(map[string]kzg.SRS)
}
func getCachedSRS(ccs frontend.CompiledConstraintSystem) (kzg.SRS, error) {
	lock.Lock()
	defer lock.Unlock()

	if srs, ok := srsCache[ccs.Modulus().Text(16)]; ok {
		return srs, nil
	}

	srs, err := newKZGSRS(ccs.Modulus(), srsCachedSize)
	if err != nil {
		return nil, err
	}
	srsCache[ccs.Modulus().Text(16)] = srs
	return srs, nil
}

func newKZGSRS(q *big.Int, kzgSize uint64) (kzg.SRS, error) {

	alpha, err := rand.Int(rand.Reader, q)
	if err != nil {
		return nil, err
	}

	switch q.Text(16) {
	case ecc.BN254.Info().Fr.Modulus().Text(16):
		return kzg_bn254.NewSRS(kzgSize, alpha)
	case ecc.BLS12_381.Info().Fr.Modulus().Text(16):
		return kzg_bls12381.NewSRS(kzgSize, alpha)
	case ecc.BLS12_377.Info().Fr.Modulus().Text(16):
		return kzg_bls12377.NewSRS(kzgSize, alpha)
	case ecc.BW6_761.Info().Fr.Modulus().Text(16):
		return kzg_bw6761.NewSRS(kzgSize, alpha)
	case ecc.BLS24_315.Info().Fr.Modulus().Text(16):
		return kzg_bls24315.NewSRS(kzgSize, alpha)
	case ecc.BW6_633.Info().Fr.Modulus().Text(16):
		return kzg_bw6633.NewSRS(kzgSize, alpha)
	default:
		panic("unrecognized R1CS curve type")
	}
}
