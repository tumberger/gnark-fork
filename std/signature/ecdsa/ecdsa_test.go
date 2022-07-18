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
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/nonnative"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type emulatedField struct {
	params  *nonnative.Params
	name    string
	modulus *big.Int
	nbBits  int
}

func getFpFr(t *testing.T) [2]emulatedField {
	t.Helper()

	var ret [2]emulatedField

	{
		var modulus big.Int
		modulus.SetString("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10)

		em, err := nonnative.NewParams(32, new(big.Int).SetBytes([]byte{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
		}))
		if err != nil {
			t.Fatal(err)
		}
		ret[0] = emulatedField{em, "secp256k1Fp", &modulus, 256}
	}

	{
		var modulus big.Int
		modulus.SetString("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10)

		em, err := nonnative.NewParams(32, new(big.Int).SetBytes([]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
			0xd0, 0x36, 0x41, 0x41,
		}))
		if err != nil {
			t.Fatal(err)
		}
		ret[1] = emulatedField{em, "secp256k1Fr", &modulus, 256}
	}

	return ret
}

var testPrivHex = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"

// returns sig, msg
func sign(t *testing.T) ([]byte, []byte, error) {

	key, _ := crypto.HexToECDSA(testPrivHex)

	msg := crypto.Keccak256([]byte("foo"))
	sig, err := crypto.Sign(msg, key)
	if err != nil {
		t.Errorf("Sign error: %s", err)
	}

	return sig, msg, nil

}

// TestEcdsa ecdsa test circuit
type EcdsaTest struct {

	// Signature, public key
	Signature Sig
	PublicKey PublicKey `gnark:",public"`

	// base point
	Base PublicKey `gnark:",public"`

	// respectively the group size and field of definition of secp256k1
	Fr, Fp *nonnative.Params
}

func (c *EcdsaTest) Define(api frontend.API) error {

	// wrapper for the non native arithmetic
	apiR := nonnative.NewAPI(api, c.Fr)
	apiP := nonnative.NewAPI(api, c.Fp)

	// check the signature
	VerifySignature(c.Signature, c.PublicKey, c.Base, apiR, apiP)

	return nil

}

func TestEcdsa(t *testing.T) {

	// generate a valid signature
	sig, msg, err := sign(t)
	if err != nil {
		t.Fatal(err)
	}

	// check that the signature is correct
	pub, err := crypto.Ecrecover(msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	sig = sig[:len(sig)-1]
	if !crypto.VerifySignature(pub, msg, sig) {
		t.Errorf("can't verify signature with uncompressed key")
	}

	var r, s, m, px, py, bx, by big.Int
	r.SetBytes(sig[:32])
	s.SetBytes(sig[32:])
	m.SetBytes(msg)
	px.SetBytes(pub[:32])
	py.SetBytes(pub[32:])

	fmt.Printf("%s\n", px.String())
	fmt.Printf("%s\n", py.String())

	bx.Set(secp256k1.S256().Gx)
	by.Set(secp256k1.S256().Gy)

	fields := getFpFr(t)

	// circuit
	var circuit EcdsaTest
	circuit.Fp = fields[0].params
	circuit.Fr = fields[1].params

	// witness
	var witness EcdsaTest
	witness.Fp = fields[0].params
	witness.Fr = fields[1].params
	// witness.PublicKey.X = witness.Fr.ConstantFromBigOrPanic()

	// fmt.Printf("R = %s\n", r.String())
	// fmt.Printf("S = %s\n", s.String())
	// fmt.Printf("m = %s\n", m.String())

	// _pub, err := crypto.UnmarshalPubkey(pub)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// secpCurve := secp256k1.S256()
	// fmt.Printf("Gx: %s\n", secpCurve.Gx.String())
	// fmt.Printf("Gy: %s\n", secpCurve.Gy.String())
	// n := secpCurve.Params().N.BitLen()
	// fmt.Printf("secpCurve.Params().N.BitLen(): %d\n", n)

	// fmt.Printf("X: %s\n", _pub.X.String())
	// fmt.Printf("Y: %s\n", _pub.Y.String())

	// check the circuit

}
