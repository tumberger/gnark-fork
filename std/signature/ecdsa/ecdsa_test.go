package ecdsa

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
)

var testPrivHex = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"

func sign(t *testing.T) ([]byte, []byte, error) {
	t.Helper()
	key, _ := crypto.HexToECDSA(testPrivHex)
	msg := crypto.Keccak256([]byte("foo"))
	sig, err := crypto.Sign(msg, key)
	if err != nil {
		t.Errorf("Sign error: %s", err)
	}
	return sig, msg, nil
}

type EcdsaCircuit[T, S emulated.FieldParams] struct {
	Sig Signature[S]
	Msg emulated.Element[S]
	Pub PublicKey[T, S]
}

func (c *EcdsaCircuit[T, S]) Define(api frontend.API) error {
	c.Pub.Verify(api, c.Msg, c.Sig)
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

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	m := new(big.Int).SetBytes(msg)

	_pub, err := crypto.UnmarshalPubkey(pub)
	if err != nil {
		t.Fatal(err)
	}

	circuit := EcdsaCircuit[emulated.Secp256k1, emulated.Secp256k1Scalars]{}
	witness := EcdsaCircuit[emulated.Secp256k1, emulated.Secp256k1Scalars]{
		Sig: Signature[emulated.Secp256k1Scalars]{
			R: emulated.NewElement[emulated.Secp256k1Scalars](r),
			S: emulated.NewElement[emulated.Secp256k1Scalars](s),
		},
		Msg: emulated.NewElement[emulated.Secp256k1Scalars](m),
		Pub: PublicKey[emulated.Secp256k1, emulated.Secp256k1Scalars]{
			X: emulated.NewElement[emulated.Secp256k1](_pub.X),
			Y: emulated.NewElement[emulated.Secp256k1](_pub.Y),
		},
	}
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	// _, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	// assert.NoError(err)
}
