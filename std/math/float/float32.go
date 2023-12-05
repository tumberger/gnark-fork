package float32

import (
	"fmt"
	"math"

	"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark/std/internal/logderivprecomp"
)

type Float32 struct {
	Exponent frontend.Variable
	Mantissa frontend.Variable
}

type RealNumberField[T Float32] struct {
	api        frontend.API
	xorT, andT *logderivprecomp.Precomputed
}

type Float interface{ Float32 }

func New[T Float](api frontend.API) (*RealNumberField[T], error) {
	xorT, err := logderivprecomp.New(api, xorHint, []uint{2})
	if err != nil {
		return nil, fmt.Errorf("new xor table: %w", err)
	}

	andT, err := logderivprecomp.New(api, andHint, []uint{8})
	if err != nil {
		return nil, fmt.Errorf("new and table: %w", err)
	}

	rnf := &RealNumberField[T]{
		api:  api,
		xorT: xorT,
		andT: andT,
	}
	return rnf, nil
}

func (rf *RealNumberField[T]) mul(p int, floatOne Float32, floatTwo Float32) [2]frontend.Variable {

	var result [2]frontend.Variable

	e := rf.api.Add(floatOne.Exponent, floatTwo.Exponent)

	// TODO: This is missing the middle term of
	// m = α1.m * 2^(q+2) * α2.m
	m := rf.api.Mul(floatOne.Mantissa, floatTwo.Mantissa)

	compareVal := rf.api.Sub(int(math.Pow(2, float64(2*p+1))), int(math.Pow(2, float64(p-1))))
	check := rf.api.IsZero(rf.api.Sub(rf.api.Cmp(compareVal, m), 1)) // Check if 2^2p+1 - 2^p-1 > m?

	// Allgemein mit modulo
	// TODO: Implement Right Shift Hint
	case1 := rightShift(rf.api, rf.api.Add(m, int(math.Pow(2, float64(p-1)))), p, 2*p+2)
	case2 := rightShift(rf.api, rf.api.Add(m, int(math.Pow(2, float64(p)))), p+1, 2*p+2)

	// Are these strictly necessary?
	result[0] = rf.api.Select(check, e, rf.api.Add(e, 1))
	result[1] = rf.api.Select(check, case1, case2)

	// TODO:
	// For the sign bit, bit-wise operations can be implemented with precomputed lookup tables
	// See Uint8 implementation - https://github.com/Consensys/gnark/blob/master/std/math/uints/uint8.go

	return result
}

// spaeter die funktion generisch machen und precision als konstante uebergeben
func (rf *RealNumberField[T]) add(k int, p int, floatOne Float32, floatTwo Float32) [2]frontend.Variable {

	// [1-bit | 23-bit mantissa | 8-bit exponent ]

	// Assumes a normalized mantissa in range [2^p, 2^p+1) and 8-bit exponent as input
	// TODO: if `e` is zero, then `m` must be zero

	mgn1 := rf.api.Add(floatOne.Mantissa, leftShift(rf.api, floatOne.Exponent, p+1, k))
	mgn2 := rf.api.Add(floatTwo.Mantissa, leftShift(rf.api, floatTwo.Exponent, p+1, k))

	check := rf.api.IsZero(rf.api.Sub(rf.api.Cmp(mgn1, mgn2), 1)) // Check if mgn1 > mgn2?
	alphaE := rf.api.Select(check, floatOne.Exponent, floatTwo.Exponent)
	alphaM := rf.api.Select(check, floatOne.Mantissa, floatTwo.Mantissa)
	betaE := rf.api.Select(check, floatTwo.Exponent, floatOne.Exponent)
	betaM := rf.api.Select(check, floatTwo.Mantissa, floatOne.Mantissa)

	diff := rf.api.Sub(alphaE, betaE)

	// if Abfrage mit diff und theoretisch return?
	result, err := rf.api.Compiler().NewHint(leftShiftHint, 1, alphaM, diff)
	if err != nil {
		panic(err)
	}
	alphaM = result[0]

	m := rf.api.Add(alphaM, betaM)

	normalized := normalize(rf.api, p, betaE, m)
	return roundAndCheck(rf.api, p, normalized[0], normalized[1])
}

// spaeter k (bit size of e), p und 2p+1 als variable uebergeben
func roundAndCheck(api frontend.API, p int, e frontend.Variable, m frontend.Variable) [2]frontend.Variable {

	var rounded [2]frontend.Variable

	// Allgemeiner Fall:  if m >= ((2 ** (P+1)) - (2 ** (P-p-1))):
	tmp := int(math.Pow(2, float64(2*p+2))) - int(math.Pow(2, float64(p)))
	compareVal := frontend.Variable(tmp)

	check := api.IsZero(api.Sub(api.Cmp(compareVal, m), 1)) // Check if 2^2p+2 - 2^p > m?

	// size checken fuer 32bit float und richtig angeben
	roundedM := rightShift(api, api.Add(m, int(math.Pow(2, float64(p)))), p+1, 2*p+2)

	rounded[0] = api.Select(check, e, api.Add(e, 1))
	rounded[1] = api.Select(check, roundedM, int(math.Pow(2, float64(p))))

	return rounded
}

// spaeter k (bit size of e), p und 2p+1 als variable uebergeben
func normalize(api frontend.API, p int, e frontend.Variable, m frontend.Variable) [2]frontend.Variable {

	var normalized [2]frontend.Variable

	ell := msnzb(api, m, 2*p+2)

	shiftM := api.Sub(2*p+1, ell)

	result, err := api.Compiler().NewHint(leftShiftHint, 1, m, shiftM)
	if err != nil {
		panic(err)
	}
	normalized[1] = result[0]

	normalized[0] = api.Sub(api.Add(e, ell), p) // e = e + ell - p

	return normalized
}

func msnzb(api frontend.API, in frontend.Variable, size int) frontend.Variable {

	//api.AssertNotZero(in)
	limit := int(math.Pow(2, float64(size)))
	api.AssertIsLessOrEqual(in, limit)

	res := frontend.Variable(0)
	notFoundBool := frontend.Variable(1)
	api.AssertIsBoolean(notFoundBool)

	for i := 0; i < size; i++ {

		lower := int(math.Pow(2, float64(i)))
		higher := int(math.Pow(2, float64(i+1)))

		checkLowStrict := api.IsZero(api.Sub(api.Cmp(in, lower), 1)) // Check if in > 2^i?
		checkLowEqual := api.IsZero(api.Sub(in, lower))              // Check if in == 2^i?
		// Set checkLow to 1 if checkLowEqual OR checkLowStrict is true
		checkLow := api.Select(checkLowEqual, 1, api.Select(checkLowStrict, 1, 0))
		checkHigh := api.IsZero(api.Sub(api.Cmp(higher, in), 1)) // Check if 2^(i+1) > in?

		// first i value to fullfill 2^i <= in < 2^(i+1) is stored in res
		tmp := api.Select(checkLow, api.Select(checkHigh, i, 0), 0)
		res = api.Select(notFoundBool, tmp, res)
		notFoundBool = api.Select(checkLow, api.Select(checkHigh, 0, notFoundBool), notFoundBool)
	}

	api.Println(res)

	return res
}

func leftShift(api frontend.API, in frontend.Variable, shift int, size int) frontend.Variable {

	// is shift + size more than possible?

	bitsIn := api.ToBinary(in, size)
	x := make([]frontend.Variable, (size + shift))

	for i := (size + shift - 1); i >= 0; i-- {

		if i < shift {
			x[i] = frontend.Variable(0)
		} else {
			x[i] = bitsIn[i-shift]
		}
	}

	res := api.FromBinary(x...)

	return res
}

func rightShift(api frontend.API, in frontend.Variable, shift int, size int) frontend.Variable {

	// is shift < size?

	bitsIn := api.ToBinary(in, size)
	x := make([]frontend.Variable, size)

	for i := 0; i < size; i++ {

		//x[i] = bitsIn[shift+i]
		if i >= (size - shift) {
			x[i] = frontend.Variable(0)
		} else {
			x[i] = bitsIn[shift+i]
		}
	}

	res := api.FromBinary(x...)

	return res
}
