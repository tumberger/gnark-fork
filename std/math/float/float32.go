package float32

import (
	"fmt"
	"math"

	"github.com/consensys/gnark/frontend"
	comparator "github.com/consensys/gnark/std/math/cmp"

	// utils "float32/utils"

	// hints "github.com/consensys/gnark/std/math/float32/hints"

	// "github.com/consensys/gnark/std/math/float32/hints"

	"github.com/consensys/gnark/std/internal/logderivprecomp"
)

const (
	Precision = 23
)

type Float32 struct {
	Exponent frontend.Variable
	Mantissa frontend.Variable
	Sign     frontend.Variable
}

type RealNumberField[T Float32] struct {
	api        frontend.API
	xorT, andT *logderivprecomp.Precomputed
	shiftT     *logderivprecomp.Precomputed
}

type Float interface{ Float32 }

func New[T Float](api frontend.API) (*RealNumberField[T], error) {
	xorT, err := logderivprecomp.New(api, xorHint, []uint{2})
	if err != nil {
		return nil, fmt.Errorf("new xor table: %w", err)
	}

	andT, err := logderivprecomp.New(api, andHint, []uint{2})
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

func (rf *RealNumberField[T]) multiplyFloat32(k int, floatOne Float32, floatTwo Float32) Float32 {

	var result Float32
	result.Exponent = rf.api.Add(floatOne.Exponent, floatTwo.Exponent)

	result.Mantissa = rf.api.Mul(floatOne.Mantissa, floatTwo.Mantissa)

	res, err := rf.api.Compiler().NewHint(ModuloHint, 1, result.Mantissa, int(math.Pow(2, float64(2*Precision+2))))
	if err != nil {
		panic(err)
	}
	result.Mantissa = res[0]

	// The following is 1 constraint
	compareVal := uint64(math.Pow(2, float64(2*Precision+1))) - uint64(math.Pow(2, float64(Precision-1)))

	// This is costly - currently relies on binary decomposition and yields ~1000 constraints
	// Check if 2^2p+1 - 2^Precision-1 > m?
	check := comparator.IsLessOrEqual(rf.api, result.Mantissa, compareVal)

	// TODO - REPLACE WITH LOOKUP
	// The following is 50 constraints
	tmp1 := rightShift(rf.api, rf.api.Add(result.Mantissa, uint64(math.Pow(2, float64(Precision-1)))), Precision, 2*Precision+2)
	// The following is 50 constraints
	tmp2 := rightShift(rf.api, rf.api.Add(result.Mantissa, uint64(math.Pow(2, float64(Precision)))), Precision+1, 2*Precision+2)

	res, err = rf.api.Compiler().NewHint(ModuloHint, 1, tmp1, uint64(math.Pow(2, float64(Precision+1))))
	if err != nil {
		panic(err)
	}
	case1 := res[0]
	res, err = rf.api.Compiler().NewHint(ModuloHint, 1, tmp2, uint64(math.Pow(2, float64(Precision+1))))
	if err != nil {
		panic(err)
	}
	case2 := res[0]

	// Are these strictly necessary?
	result.Exponent = rf.api.Select(check, result.Exponent, rf.api.Add(result.Exponent, 1))
	result.Mantissa = rf.api.Select(check, case1, case2)

	result = checkOverUnderFlows(rf.api, k, result)

	return result
}

func greaterThan(api frontend.API, k int, floatOne Float32, floatTwo Float32) frontend.Variable {

	// Make exponents positive for correct comparison
	floatOne.Exponent = api.Add(floatOne.Exponent, int(math.Pow(2, float64(k-1)))-1)
	floatTwo.Exponent = api.Add(floatTwo.Exponent, int(math.Pow(2, float64(k-1)))-1)

	// Check if e1 > e2?
	eLT := api.Sub(1, comparator.IsLess(api, floatOne.Exponent, floatTwo.Exponent))
	// Check if e1 == e2?
	eEQ := api.IsZero(api.Sub(floatOne.Exponent, floatTwo.Exponent))
	// Check if x[1] > y[1]?
	mLT := api.Sub(1, comparator.IsLess(api, floatOne.Mantissa, floatTwo.Mantissa))

	eEQANDmLT := api.Select(eEQ, mLT, 0)

	return api.Select(eLT, api.Sub(1, eEQANDmLT), eEQANDmLT)
}

func AddFloat32(api frontend.API, k int, p int, FloatOne Float32, FloatTwo Float32) [3]frontend.Variable {

	// [1-bit | 23-bit mantissa | 8-bit exponent ]

	// Assumes a normalized mantissa in range [2^p, 2^p+1) and k-bit exponent as input
	limit := int(math.Pow(2, float64(p+1))) - 1
	api.AssertIsLessOrEqual(FloatOne.Mantissa, limit)
	api.AssertIsLessOrEqual(FloatOne.Mantissa, limit)

	// TODO: if `e` is zero, then `m` must be zero

	var ret [3]frontend.Variable

	check := greaterThan(api, k, FloatOne, FloatTwo)

	alphaE := api.Select(check, FloatTwo.Exponent, FloatOne.Exponent)
	alphaM := api.Select(check, FloatOne.Mantissa, FloatOne.Mantissa)
	alphaS := api.Select(check, FloatTwo.Sign, FloatOne.Sign)
	betaE := api.Select(check, FloatOne.Exponent, FloatTwo.Exponent)
	betaM := api.Select(check, FloatOne.Mantissa, FloatTwo.Mantissa)
	betaS := api.Select(check, FloatOne.Sign, FloatTwo.Sign)

	diff := api.Sub(alphaE, betaE)
	api.Println(diff)

	// the smaller exp value will be ignored during the final rounding step if diff > p+1
	ignored := api.IsZero(api.Sub(api.Cmp(diff, (p+1)), 1)) // Check if diff > p+1?

	// make sure argument for shift isn't negative -- if negative Cmp returns -1
	api.AssertIsBoolean(api.Cmp(diff, 0))
	shifted, err := api.Compiler().NewHint(LeftShiftHint, 1, alphaM, diff)
	if err != nil {
		panic(err)
	}
	alphaM = api.Select(ignored, alphaM, shifted[0])
	//api.Println(alphaM)

	subtract := api.Select(alphaS, api.Select(betaS, 0, 1), betaS)
	// WHAT IF betaM MUCH LARGER AND SUBTRACTED?
	m := api.Select(subtract, api.Sub(alphaM, betaM), api.Add(alphaM, betaM))
	stub := BaseM
	m = api.Select(ignored, stub, m)
	//api.Println(m)

	var FloatTemp Float32

	FloatTemp.Exponent = betaM
	FloatTemp.Mantissa = m

	FloatNormalized := normalize(api, p, FloatTemp)
	FloatRounded := roundAndCheck(api, p, FloatNormalized)
	checked := checkOverUnderFlows(api, k, FloatRounded)

	ret[0] = alphaS
	ret[1] = api.Select(ignored, alphaE, checked.Exponent)
	ret[2] = api.Select(ignored, alphaM, checked.Mantissa)

	api.Println(ret)

	return ret
}

func checkOverUnderFlows(api frontend.API, k int, value Float32) Float32 {

	var result Float32

	// Make exponent positive for correct comparison
	value.Exponent = api.Add(value.Exponent, int(math.Pow(2, float64(k-1))))

	upperBound := int(math.Pow(2, float64(k))) - 1

	// Check if e > 2^(k-1) - 1?
	check := api.Sub(1, comparator.IsLessOrEqual(api, value.Exponent, upperBound))

	value.Exponent = api.Select(check, upperBound, value.Exponent)
	value.Mantissa = api.Select(check, int(math.Pow(2, float64(Precision))), value.Mantissa)

	// Lower Bound Check
	// Updated lowerBound to be 2 - 2^(p-1)
	lowerBound := int(math.Pow(2, float64(k-1))) - 1
	lowerBoundCheck := 2 - lowerBound

	// Check if e < 2 - 2^(p-1) using comparator.IsLess
	check = api.Sub(1, comparator.IsLess(api, value.Exponent, lowerBoundCheck))

	// If e < 2 - 2^(p-1), then set m = 0; e = 1 - 2^(p-1)
	underflowExponent := 1 - lowerBound
	value.Exponent = api.Select(check, underflowExponent, value.Exponent)
	value.Mantissa = api.Select(check, 0, value.Mantissa)

	// Reset exponent after comparison
	result.Exponent = api.Sub(value.Exponent, int(math.Pow(2, float64(k-1))))
	result.Mantissa = value.Mantissa

	return result
}

// func (rf *RealNumberField[T]) add(k int, p int, floatOne Float32, floatTwo Float32) frontend.Variable {

// 	mgn1 := rf.api.Add(floatOne.Mantissa, leftShift(rf.api, floatOne.Exponent, p+1, k))
// 	mgn2 := rf.api.Add(floatTwo.Mantissa, leftShift(rf.api, floatTwo.Exponent, p+1, k))

// 	check := rf.api.IsZero(rf.api.Sub(rf.api.Cmp(mgn1, mgn2), 1))

// 	alphaE := rf.api.Select(check, floatOne.Exponent, floatTwo.Exponent)
// 	alphaM := rf.api.Select(check, floatOne.Mantissa, floatTwo.Mantissa)
// 	betaE := rf.api.Select(check, floatTwo.Exponent, floatOne.Exponent)
// 	betaM := rf.api.Select(check, floatTwo.Mantissa, floatOne.Mantissa)

// 	diff := rf.api.Sub(alphaE, betaE)

// 	result, err := rf.api.Compiler().NewHint(LeftShiftHint, 1, alphaM, diff)
// 	if err != nil {
// 		panic(err)
// 	}

// 	alphaM = result[0]

// 	m := rf.api.Add(alphaM, betaM)

// 	normalized := normalize(rf.api, p, betaE, m)

// 	rf.api.Println(alphaE, alphaM, betaE, betaM, diff, result, m, normalized)

// 	return check
// }

// spaeter die funktion generisch machen und precision als konstante uebergeben
// func (rf *RealNumberField[T]) addOld(k int, p int, floatOne Float32, floatTwo Float32) [2]frontend.Variable {

// 	// [1-bit | 23-bit mantissa | 8-bit exponent ]

// 	// Assumes a normalized mantissa in range [2^p, 2^p+1) and 8-bit exponent as input
// 	// TODO: if `e` is zero, then `m` must be zero

// 	mgn1 := rf.api.Add(floatOne.Mantissa, leftShift(rf.api, floatOne.Exponent, p+1, k))
// 	mgn2 := rf.api.Add(floatTwo.Mantissa, leftShift(rf.api, floatTwo.Exponent, p+1, k))

// 	check := rf.api.IsZero(rf.api.Sub(rf.api.Cmp(mgn1, mgn2), 1)) // Check if mgn1 > mgn2?
// 	alphaE := rf.api.Select(check, floatOne.Exponent, floatTwo.Exponent)
// 	alphaM := rf.api.Select(check, floatOne.Mantissa, floatTwo.Mantissa)
// 	betaE := rf.api.Select(check, floatTwo.Exponent, floatOne.Exponent)
// 	betaM := rf.api.Select(check, floatTwo.Mantissa, floatOne.Mantissa)

// 	diff := rf.api.Sub(alphaE, betaE)

// 	// if Abfrage mit diff und theoretisch return?
// 	result, err := rf.api.Compiler().NewHint(LeftShiftHint, 1, alphaM, diff)
// 	if err != nil {
// 		panic(err)
// 	}
// 	alphaM = result[0]

// 	m := rf.api.Add(alphaM, betaM)

// 	normalized := normalize(rf.api, p, betaE, m)
// 	return roundAndCheck(rf.api, p, normalized[0], normalized[1])
// }

// spaeter k (bit size of e), p und 2p+1 als variable uebergeben
func roundAndCheck(api frontend.API, k int, Float Float32) Float32 {

	var rounded Float32

	// Allgemeiner Fall:  if m >= ((2 ** (P+1)) - (2 ** (P-p-1))):
	tmp := int(math.Pow(2, float64(2*Precision+2))) - int(math.Pow(2, float64(Precision)))
	compareVal := frontend.Variable(tmp)

	// Check if 2^2p+2 - 2^p > m?
	check := api.IsZero(api.Sub(api.Cmp(compareVal, Float.Mantissa), 1))

	// size checken fuer 32bit float und richtig angeben
	roundedM := rightShift(api, api.Add(Float.Mantissa, int(math.Pow(2, float64(Precision)))), Precision+1, 2*Precision+2)

	rounded.Exponent = api.Select(check, Float.Exponent, api.Add(Float.Exponent, 1))
	rounded.Mantissa = api.Select(check, roundedM, int(math.Pow(2, float64(Precision))))

	return rounded
}

// spaeter k (bit size of e), p und 2p+1 als variable uebergeben
func normalize(api frontend.API, p int, Float Float32) Float32 {

	var normalized Float32

	ell := msnzb(api, Float.Mantissa, 2*p+2)

	shiftM := api.Sub(2*p+1, ell)

	result, err := api.Compiler().NewHint(LeftShiftHint, 1, Float.Mantissa, shiftM)
	if err != nil {
		panic(err)
	}
	normalized.Mantissa = result[0]

	normalized.Exponent = api.Sub(api.Add(Float.Exponent, ell), p) // e = e + ell - p

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
