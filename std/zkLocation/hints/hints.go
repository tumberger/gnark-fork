package hints

import (
	"fmt"
	"math/big"
)

func IntegerDivisionHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {

	if len(inputs) != 2 {
		return fmt.Errorf("integer division expects 2 operands")
	}

	// for i, operand := range inputs {
	// 	println("IntegerDivisionHint: operand[", i, "] is", operand.String())
	// }

	res := new(big.Int).Div(inputs[0], inputs[1])

	// println("Integer Division result is", res.String())

	results[0] = res

	return nil
}

func ModuloHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {

	if len(inputs) != 2 {
		return fmt.Errorf("modulo operation expects 2 operands")
	}

	// for i, operand := range inputs {
	//         println("ModuloHint: operand[", i, "] is", operand.String())
	// }

	remainder := new(big.Int).Rem(inputs[0], inputs[1])

	// println("Remainder is", remainder.String())

	results[0] = remainder

	return nil
}
