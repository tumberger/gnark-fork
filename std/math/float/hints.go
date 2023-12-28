package float32

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

func GetHints() []solver.Hint {
	return []solver.Hint{
		LeftShiftHint,
		ModuloHint,
		LookupHint,
		xorHint,
		andHint,
		toBits,
	}
}

func LeftShiftHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {

	if len(inputs) != 2 {
		return fmt.Errorf("left shift hint expects 2 operands")
	}

	shift := inputs[1].Uint64()
	results[0].Lsh(inputs[0], uint(shift))
	println("Left shift result is", results[0].String())

	return nil
}

func ModuloHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {

	if len(inputs) != 2 {
		return fmt.Errorf("modulo operation expects 2 operands")
	}

	remainder := new(big.Int).Rem(inputs[0], inputs[1])

	//println("Remainder is", remainder.String())

	results[0] = remainder

	return nil
}

func LookupHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {

	if len(inputs) != 1 {
		return fmt.Errorf("lookup hint expects only 1 operand")
	}

	lookup := [256]uint64{255, 253, 251, 249, 247, 245, 243, 241, 240, 238, 236, 234, 232, 230, 229, 227,
		225, 223, 221, 220, 218, 216, 215, 213, 211, 210, 208, 206, 205, 203, 201, 200,
		198, 197, 195, 194, 192, 191, 189, 188, 186, 185, 183, 182, 180, 179, 177, 176,
		174, 173, 172, 170, 169, 167, 166, 165, 163, 162, 161, 159, 158, 157, 156, 154,
		153, 152, 150, 149, 148, 147, 145, 144, 143, 142, 141, 139, 138, 137, 136, 135,
		134, 132, 131, 130, 129, 128, 127, 126, 124, 123, 122, 121, 120, 119, 118, 117,
		116, 115, 114, 113, 112, 111, 110, 109, 108, 107, 106, 105, 104, 103, 102, 101,
		100, 99, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89, 88, 88, 87, 86,
		85, 84, 83, 82, 81, 81, 80, 79, 78, 77, 76, 75, 75, 74, 73, 72,
		71, 70, 70, 69, 68, 67, 66, 66, 65, 64, 63, 63, 62, 61, 60, 59,
		59, 58, 57, 56, 56, 55, 54, 53, 53, 52, 51, 51, 50, 49, 48, 48,
		47, 46, 46, 45, 44, 44, 43, 42, 42, 41, 40, 40, 39, 38, 38, 37,
		36, 36, 35, 34, 34, 33, 32, 32, 31, 30, 30, 29, 29, 28, 27, 27,
		26, 26, 25, 24, 24, 23, 23, 22, 21, 21, 20, 20, 19, 18, 18, 17,
		17, 16, 16, 15, 15, 14, 13, 13, 12, 12, 11, 11, 10, 10, 9, 9,
		8, 7, 7, 6, 6, 5, 5, 4, 4, 3, 3, 2, 2, 1, 1, 0}

	index := inputs[0].Uint64()
	results[0] = new(big.Int).SetUint64(lookup[uint(index)])
	println("Lookup result is", results[0].String())

	return nil
}

func xorHint(_ *big.Int, inputs, outputs []*big.Int) error {
	outputs[0].Xor(inputs[0], inputs[1])
	return nil
}

func andHint(_ *big.Int, inputs, outputs []*big.Int) error {
	outputs[0].And(inputs[0], inputs[1])
	return nil
}

func toBits(m *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return fmt.Errorf("input must be 2 elements")
	}
	if !inputs[0].IsUint64() {
		return fmt.Errorf("first input must be uint64")
	}
	nbBits := int(inputs[0].Uint64())
	if len(outputs) != nbBits {
		return fmt.Errorf("output must have the same number of elements as the number of bits")
	}
	if !inputs[1].IsUint64() {
		return fmt.Errorf("input must be 64 bits")
	}
	base := big.NewInt(2)
	tmp := new(big.Int).Set(inputs[1])
	for i := 0; i < nbBits; i++ {
		outputs[i].Mod(tmp, base)
		tmp.Rsh(tmp, 1)
	}
	return nil
}
