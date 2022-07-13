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

	"github.com/ethereum/go-ethereum/crypto"
)

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

	var r, s, m big.Int
	r.SetBytes(sig[:32])
	s.SetBytes(sig[32:])
	m.SetBytes(msg)
	fmt.Printf("R = %s\n", r.String())
	fmt.Printf("S = %s\n", s.String())
	fmt.Printf("m = %s\n", m.String())

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
