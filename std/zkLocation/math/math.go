package math

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/zkLocation/hints"
	"github.com/consensys/gnark/std/zkLocation/util"
)

func Sine(api frontend.API, term frontend.Variable) frontend.Variable {

	res := frontend.Variable(0)
	api.AssertIsLessOrEqual(term, util.Pi)

	// The Taylor Series approximation's inaccuracy increases when the input is close to pi
	// we mitigate this with the symmetry of the function
	// Since sin(x) is symmetric at pi/2, we fold across the symmetry axis in case term > pi/2
	greaterHalfPi := api.IsZero(api.Sub(api.Cmp(term, util.HalfPi), 1))
	folding := api.Sub(term, util.HalfPi)
	term = api.Select(greaterHalfPi, api.Sub(util.HalfPi, folding), term)

	result, err := api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(term, term), 1000000000)
	if err != nil {
		panic(err)
	}
	xSquare := result[0] // 10^9-based result
	resIsNegative := frontend.Variable(0)

	// Calculate Approximation as Taylor Series Expansion
	for i := 1000000000; i < 14000000000; i += 1000000000 {

		// Alternating addition and subtraction on 'term' variable
		// We compare 'term' and current result, then operate accordingly
		api.AssertIsBoolean(resIsNegative)

		if (i/1000000000)%2 == 0 {
			check := api.IsZero(api.Sub(api.Cmp(term, res), 1)) // Check if term > res?
			res = api.Select(check, api.Sub(term, res), api.Sub(res, term))
			resIsNegative = check
		} else {
			resNeg := api.Sub(term, res)
			resPos := api.Add(res, term)
			res = api.Select(resIsNegative, resNeg, resPos)

			resIsNegative = frontend.Variable(0)
		}

		// Calculate term*x^2 / 2i*(2i+1) in each loop iteration
		intm := api.Div(api.Mul(2000000000, i), 1000000000)                      // 10^9-based result
		divisor := api.Div(api.Mul(intm, api.Add(intm, 1000000000)), 1000000000) // 10^9
		xPoly := api.Mul(term, xSquare)                                          // 10^18 for division below

		result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, xPoly, divisor)
		if err != nil {
			panic(err)
		}

		term = result[0]

		lower := api.Mul(term, divisor)
		higher := api.Add(lower, divisor)

		api.AssertIsLessOrEqual(lower, xPoly)
		api.AssertIsBoolean(api.Cmp(higher, xPoly))
	}

	return res
}

// We approximate the arctan(x) in the range [0,1] with a polynomial of degree 7,
// the Remez algorithm has supplied us with the appropriate constants
// Below is our fairly simple polynomial calculation as pseudo code:
//
// u = 22023164
// u = u * x / 1000000000 - 133745220
// u = u * x / 1000000000 + 329466520
// u = u * x / 1000000000 - 379059430
// u = u * x / 1000000000 + 105311900
// u = u * x / 1000000000 + 169820680
// u = u * x / 1000000000 + 5476566
// u = u * x / 1000000000 - 333930430
// u = u * x / 1000000000 + 35325
// u = u * x / 1000000000 + 999999050
// u = u * x / 1000000000 + 408
func AtanRemez(api frontend.API, x1 frontend.Variable) frontend.Variable {

	// We start by distinguishing if x>1
	// if x>1 then arctan(x) = pi/2 - arctan(1/x)
	// We convert the input to 1/x in case x > 1
	greaterOne := api.IsZero(api.Sub(api.Cmp(x1, 1000000000), 1))

	x1 = api.Select(api.IsZero(x1), 1, x1) // Avoid division by zero

	// Dividing 1*10^18 by 10^9 number for 10^9 result
	recipical, recErr := api.Compiler().NewHint(hints.IntegerDivisionHint, 1, 1000000000000000000, x1)
	if recErr != nil {
		panic(recErr)
	}

	x1 = api.Select(greaterOne, recipical[0], x1)

	// Starting Remez polynomial approximation
	const1 := frontend.Variable(22023164)
	const2 := frontend.Variable(133745220) // negative value
	const3 := frontend.Variable(329466520)
	const4 := frontend.Variable(379059430) // negative value
	const5 := frontend.Variable(105311900)
	const6 := frontend.Variable(169820680)
	const7 := frontend.Variable(5476566)
	const8 := frontend.Variable(333930430) // negative value
	const9 := frontend.Variable(35325)
	const10 := frontend.Variable(999999050)
	const11 := frontend.Variable(7)

	// First multiplication -- const1 positive and const2 negative
	result, err := api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(x1, const1), 1000000000)
	if err != nil {
		panic(err)
	}
	res := result[0]                                      // 10^9-based result
	check := api.IsZero(api.Sub(api.Cmp(const2, res), 1)) // Check if const2 > res?
	res = api.Select(check, api.Sub(const2, res), api.Sub(res, const2))
	resIsNegative := check

	// Second multiplication -- const3 positive
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(x1, res), 1000000000)
	if err != nil {
		panic(err)
	}
	res = result[0]                                      // 10^9-based result
	check = api.IsZero(api.Sub(api.Cmp(const3, res), 1)) // Check if const3 > res?
	res = api.Select(resIsNegative,
		api.Select(check, api.Sub(const3, res), api.Sub(res, const3)),
		api.Add(res, const3))
	resIsNegative = api.Select(resIsNegative, api.Sub(1, check), 0)

	// Third multiplication -- const4 negative
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(x1, res), 1000000000)
	if err != nil {
		panic(err)
	}
	res = result[0]                                      // 10^9-based result
	check = api.IsZero(api.Sub(api.Cmp(const4, res), 1)) // Check if const4 > res?
	res = api.Select(resIsNegative,
		api.Add(res, const4),
		api.Select(check, api.Sub(const4, res), api.Sub(res, const4)))
	resIsNegative = api.Select(resIsNegative, 1, check)

	// Fourth multiplication -- const5 positive
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(x1, res), 1000000000)
	if err != nil {
		panic(err)
	}
	res = result[0]                                      // 10^9-based result
	check = api.IsZero(api.Sub(api.Cmp(const5, res), 1)) // Check if const5 > res?
	res = api.Select(resIsNegative,
		api.Select(check, api.Sub(const5, res), api.Sub(res, const5)),
		api.Add(res, const5))
	resIsNegative = api.Select(resIsNegative, api.Sub(1, check), 0)

	// Fifth multiplication -- const6 positive
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(x1, res), 1000000000)
	if err != nil {
		panic(err)
	}
	res = result[0]                                      // 10^9-based result
	check = api.IsZero(api.Sub(api.Cmp(const6, res), 1)) // Check if const6 > res?
	res = api.Select(resIsNegative,
		api.Select(check, api.Sub(const6, res), api.Sub(res, const6)),
		api.Add(res, const6))
	resIsNegative = api.Select(resIsNegative, api.Sub(1, check), 0)

	// Sixth multiplication -- const7 positive
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(x1, res), 1000000000)
	if err != nil {
		panic(err)
	}
	res = result[0]                                      // 10^9-based result
	check = api.IsZero(api.Sub(api.Cmp(const7, res), 1)) // Check if const7 > res?
	res = api.Select(resIsNegative,
		api.Select(check, api.Sub(const7, res), api.Sub(res, const7)),
		api.Add(res, const7))
	resIsNegative = api.Select(resIsNegative, api.Sub(1, check), 0)

	// Seventh multiplication -- const8 negative
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(x1, res), 1000000000)
	if err != nil {
		panic(err)
	}
	res = result[0]                                      // 10^9-based result
	check = api.IsZero(api.Sub(api.Cmp(const8, res), 1)) // Check if const8 > res?
	res = api.Select(resIsNegative,
		api.Add(res, const8),
		api.Select(check, api.Sub(const8, res), api.Sub(res, const8)))
	resIsNegative = api.Select(resIsNegative, 1, check)

	// Eigth multiplication -- const9 positive
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(x1, res), 1000000000)
	if err != nil {
		panic(err)
	}
	res = result[0]                                      // 10^9-based result
	check = api.IsZero(api.Sub(api.Cmp(const9, res), 1)) // Check if const9 > res?
	res = api.Select(resIsNegative,
		api.Select(check, api.Sub(const9, res), api.Sub(res, const9)),
		api.Add(res, const9))
	resIsNegative = api.Select(resIsNegative, api.Sub(1, check), 0)

	// Ninth multiplication -- const10 positive
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(x1, res), 1000000000)
	if err != nil {
		panic(err)
	}
	res = result[0]                                       // 10^9-based result
	check = api.IsZero(api.Sub(api.Cmp(const10, res), 1)) // Check if const10 > res?
	res = api.Select(resIsNegative,
		api.Select(check, api.Sub(const10, res), api.Sub(res, const10)),
		api.Add(res, const10))
	resIsNegative = api.Select(resIsNegative, api.Sub(1, check), 0)

	// Tenth and final multiplication -- const11 positive
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(x1, res), 1000000000)
	if err != nil {
		panic(err)
	}
	res = result[0]                                       // 10^9-based result
	check = api.IsZero(api.Sub(api.Cmp(const11, res), 1)) // Check if const11 > res?
	res = api.Select(resIsNegative,
		api.Select(check, api.Sub(const11, res), api.Sub(res, const11)),
		api.Add(res, const11))
	// if x is positive, the output of atan(x) is always positive and we don't need the next line
	//resIsNegative = api.Select(resIsNegative, api.Sub(1, check), 0)

	res = api.Select(greaterOne, api.Sub(util.HalfPi, res), res) // if x > 1: pi/2 - result
	return res
}

// To approximate the arctan(x) we distinguish if x>1 and if x>0,5359 (double of 2 minus sqrt of 3)
// if x>1 then arctan(x) = pi/2 - arctan(1/x)
// if x>0,5359 then arctan(x) = pi/6 + arctan( sqrt(3)*x-1 / sqrt(3)+1 )
func Atan(api frontend.API, x1 frontend.Variable) frontend.Variable {

	// We convert the input to 1/x in case x > 1
	greaterOne := api.IsZero(api.Sub(api.Cmp(x1, 1000000000), 1))

	x1 = api.Select(api.IsZero(x1), 1, x1) // Avoid division by zero

	// Dividing 1*10^18 by 10^9 number for 10^9 result
	recipical, recErr := api.Compiler().NewHint(hints.IntegerDivisionHint, 1, 1000000000000000000, x1)
	if recErr != nil {
		panic(recErr)
	}

	x1 = api.Select(greaterOne, recipical[0], x1)

	// We convert the input in case x > 2 * (2 - sqrt(3))
	substitution := api.IsZero(api.Sub(api.Cmp(x1, 535898385), 1))

	numerator_part := api.Mul(1732050808, x1)                 // 10^18
	numerator := api.Sub(numerator_part, 1000000000000000000) // 10^18 for following division

	// Also we check if x*sqrt(3) >= 1 to mitigate the case of negative input to arctan()
	positive := api.IsZero(api.Sub(api.Cmp(numerator_part, 999999999999999999), 1)) // 10^18-1
	// Map the negative values to positive with: min_mapped - (x - min_input)
	mitigation := api.Sub(535898385000000000, api.Sub(numerator_part, 464101615000000000)) // 10^18

	numerator = api.Select(positive, numerator, mitigation)
	fraction, fracErr := api.Compiler().NewHint(hints.IntegerDivisionHint, 1, numerator, 2732050808)
	if fracErr != nil {
		panic(fracErr)
	}

	x1 = api.Select(substitution, fraction[0], x1)

	// Calculate arctan(), use approximation x - x^3/3 + x^5/5
	x3 := api.Mul(x1, x1, x1) // Add check for possible overflow
	// Dividing 10^27 number by 3*10^18 for 10^9 result
	result, err := api.Compiler().NewHint(hints.IntegerDivisionHint, 1, x3, 3000000000000000000)
	if err != nil {
		panic(err)
	}
	term2 := result[0]
	lower := api.Mul(term2, 3000000000000000000)
	higher := api.Add(lower, 3000000000000000000)
	api.AssertIsLessOrEqual(lower, x3)
	api.AssertIsBoolean(api.Cmp(higher, x3))

	x5 := api.Mul(term2, x1, x1, 3) // Results in x^5 in 10^27 base
	// Dividing 10^27 number by 5*10^18 for 10^9 result
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, x5, 5000000000000000000)
	if err != nil {
		panic(err)
	}
	term3 := result[0]
	lower = api.Mul(term3, 5000000000000000000)
	higher = api.Add(lower, 5000000000000000000)
	api.AssertIsLessOrEqual(lower, x5)
	api.AssertIsBoolean(api.Cmp(higher, x5))

	res := api.Add(x1, term3)
	res = api.Sub(res, term2)

	// Readjust result if substitution on inputs was made in previous step: pi/6 +/- result
	res = api.Select(substitution,
		api.Select(positive, api.Add(523598776, res), api.Sub(523598776, res)), res)

	res = api.Select(greaterOne, api.Sub(util.HalfPi, res), res) // if x > 1: pi/2 - result

	return res
}

func Atan2(api frontend.API, arg1 frontend.Variable, arg2 frontend.Variable, arg1Negative frontend.Variable, arg2Negative frontend.Variable) [2]frontend.Variable {
	var retrn [2]frontend.Variable

	xIsZero := api.IsZero(arg2)
	arg2 = api.Select(xIsZero, 50, arg2)

	// for x =/= 0: atan2(y,x) = atan(y/x) when x>0 and atan(y/x) +/- pi if x<0
	arg1 = api.Mul(arg1, 1000000000) // making arg1 10^18 for following division
	result, err := api.Compiler().NewHint(hints.IntegerDivisionHint, 1, arg1, arg2)
	if err != nil {
		panic(err)
	}
	atanArgument := result[0] // 10^9-based result
	atanNegative := api.Select(arg1Negative, api.Sub(1, arg2Negative), arg2Negative)

	res := AtanRemez(api, atanArgument) // atan(x/y)

	atanPi := api.Select(arg1Negative, api.Select(atanNegative, api.Add(res, util.Pi), api.Sub(util.Pi, res)),
		api.Select(atanNegative, api.Sub(util.Pi, res), api.Add(util.Pi, res)))

	atan2 := api.Select(arg2Negative, atanPi, res)
	atan2Negative := api.Select(arg2Negative, arg1Negative, atanNegative)

	// In case x == 0: the result of atan2(y,x) is +/- pi/2, depending on y
	atan2 = api.Select(xIsZero, util.HalfPi, atan2)
	atan2Negative = api.Select(xIsZero, arg1Negative, atan2Negative)

	retrn[0] = atan2Negative
	retrn[1] = atan2

	return retrn
}

func SqRoot(api frontend.API, term frontend.Variable) frontend.Variable {
	// 0.000000004 -> 0.0000001 -> 0.00001 -> 0.001 -> 0.1
	// Starting point is 5
	x1 := frontend.Variable(5000000000) // 5 * 10^9

	check1 := api.IsZero(api.Sub(api.Cmp(100000000, term), 1)) // Check if 0.1 > term?
	check2 := api.IsZero(api.Sub(api.Cmp(1000000, term), 1))   // Check if 0.001 > term?
	check3 := api.IsZero(api.Sub(api.Cmp(10000, term), 1))     // Check if 0.00001 > term?
	check4 := api.IsZero(api.Sub(api.Cmp(100, term), 1))       // Check if 0.0000001 > term?

	term = api.Select(check1, api.Mul(term, 100), term)
	term = api.Select(check2, api.Mul(term, 100), term)
	term = api.Select(check3, api.Mul(term, 100), term)
	term = api.Select(check4, api.Mul(term, 100), term)

	// Calculate Square root approximation
	for i := 1000000000; i < 14000000000; i += 1000000000 {

		tmp1 := api.Mul(x1, 1000000000) // Bring x1 to 10^18 for following division
		result, err := api.Compiler().NewHint(hints.IntegerDivisionHint, 1,
			tmp1, 2000000000)
		if err != nil {
			panic(err)
		}

		summand1 := result[0]
		lower := api.Mul(summand1, 2000000000)
		higher := api.Add(lower, 2000000000)
		api.AssertIsLessOrEqual(lower, tmp1)
		api.AssertIsBoolean(api.Cmp(higher, tmp1))

		tmp1 = api.Mul(term, 1000000000000000000) // 10^9*10^18
		tmp2 := api.Mul(x1, 2000000000)           // 10^9*10^9

		result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, tmp1, tmp2)
		if err != nil {
			panic(err)
		}

		summand2 := result[0]

		x1 = api.Add(summand1, summand2)
	}

	result, err := api.Compiler().NewHint(hints.IntegerDivisionHint, 1, x1, 10)
	if err != nil {
		panic(err)
	}
	res1 := result[0]

	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, x1, 100)
	if err != nil {
		panic(err)
	}
	res2 := result[0]

	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, x1, 1000)
	if err != nil {
		panic(err)
	}
	res3 := result[0]

	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, x1, 10000)
	if err != nil {
		panic(err)
	}
	res4 := result[0]

	x1 = api.Select(check1, res1, x1)
	x1 = api.Select(check2, res2, x1)
	x1 = api.Select(check3, res3, x1)
	x1 = api.Select(check4, res4, x1)

	return x1
}
