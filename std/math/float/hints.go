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
		leftShiftHint,
		xorHint,
		andHint,
	}
}

func leftShiftHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {

	if len(inputs) != 2 {
		return fmt.Errorf("left shift hint expects 2 operands")
	}

	shift := inputs[1].Uint64()
	results[0].Lsh(inputs[0], uint(shift))
	println("Left shift result is", results[0].String())

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
