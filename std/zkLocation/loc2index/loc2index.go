package loc2index

import (
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/zkLocation/hints"
	"github.com/consensys/gnark/std/zkLocation/math"
)

type loc2IndexWrapper struct {
	// SECRET INPUTS
	Lat           frontend.Variable
	Lng           frontend.Variable
	LatIsNegative frontend.Variable
	LngIsNegative frontend.Variable

	// PUBLIC INPUTS
	I          frontend.Variable `gnark:",public"`
	J          frontend.Variable `gnark:",public"`
	K          frontend.Variable `gnark:",public"`
	Resolution frontend.Variable `gnark:",public"`
}

func init() {
	solver.RegisterHint(hints.IntegerDivisionHint)
	solver.RegisterHint(hints.ModuloHint)
}

func (circuit *loc2IndexWrapper) Define(api frontend.API) error {

	resolution := circuit.Resolution
	pi := frontend.Variable(3141592653)
	doublePi := frontend.Variable(6283185307)
	halfPi := frontend.Variable(1570796327)
	api.AssertIsLessOrEqual(resolution, 15)
	api.AssertIsLessOrEqual(circuit.Lat, halfPi)
	api.AssertIsLessOrEqual(circuit.Lng, pi)

	// Starting Vec3d calculation
	xIsNegative := api.IsZero(api.Sub(api.Cmp(circuit.Lng, halfPi), 1))
	term := api.Select(xIsNegative, api.Sub(circuit.Lng, halfPi), api.Add(circuit.Lng, halfPi))
	cosLng := math.Sine(api, term) // frontend.Variable(980066578)
	term = api.Add(circuit.Lat, halfPi)
	cosLat := math.Sine(api, term) // cos(Lat) -- always positive        frontend.Variable(667462818)

	result, err := api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(cosLng, cosLat), 1000000000)
	if err != nil {
		panic(err)
	}
	x := result[0]

	sinLng := math.Sine(api, circuit.Lng) // sin(Lng)         frontend.Variable( 198669331)

	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(sinLng, cosLat), 1000000000)
	if err != nil {
		panic(err)
	}
	y := result[0] // sign depends on sign of longitude

	z := math.Sine(api, circuit.Lat) // sin(Lat) -- sign depends on sign of latitude frontend.Variable(744643120)

	// Starting calculations depending on the closest face
	//
	// Longitude coordinates of faces for azimuth calculation
	// negative longitudes for faces 2,3,7,8,11,12,13,16,17,18
	lng0 := 1248397419
	lng1 := 2536945009
	lng2 := 1347517358
	lng3 := 450603909
	lng4 := 401988202
	lng5 := 1678146885
	lng6 := 2953923329
	lng7 := 1888876200
	lng8 := 733429513
	lng9 := 506495587
	lng10 := 2408163140
	lng11 := 2635097066
	lng12 := 1463445768
	lng13 := 187669323
	lng14 := 1252716453
	lng15 := 2690988744
	lng16 := 2739604450
	lng17 := 1893195233
	lng18 := 604647643
	lng19 := 1794075294

	latIsNegative := circuit.LatIsNegative
	lngIsNegative := circuit.LngIsNegative

	// faces with only positive xyz-coordinates:
	face0x := 219930779
	face0y := 658369178
	face0z := 719847537
	face4x := 811253470
	face4y := 344895323
	face4z := 472138773

	// Face 0
	// Calculate square distance to face center considering + and -
	check := api.IsZero(api.Sub(api.Cmp(x, face0x), 1)) // Check if x > face0x?
	summand1 := api.Select(check, api.Sub(x, face0x), api.Sub(face0x, x))
	summand1 = api.Select(xIsNegative, api.Add(x, face0x), summand1)

	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(y, face0y), 1)) // Check if y > face0y?
	summand2 := api.Select(check, api.Sub(y, face0y), api.Sub(face0y, y))
	summand2 = api.Select(lngIsNegative, api.Add(y, face0y), summand2)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(z, face0z), 1)) // Check if z > face0z?
	summand3 := api.Select(check, api.Sub(z, face0z), api.Sub(face0z, z))
	summand3 = api.Select(latIsNegative, api.Add(z, face0z), summand3)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance0 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 0 is positive
	tmpArg1Negative := api.IsZero(api.Sub(api.Cmp(lng0, circuit.Lng), 1)) // Check if face's lng > lng?
	lngPos := api.Select(tmpArg1Negative, api.Sub(lng0, circuit.Lng), api.Sub(circuit.Lng, lng0))
	diff0 := api.Select(lngIsNegative, api.Add(lng0, circuit.Lng), lngPos)
	tmpArg1Negative = api.Select(lngIsNegative, lngIsNegative, tmpArg1Negative)

	// Face 4
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(x, face4x), 1)) // Check if x > face4x?
	summand1 = api.Select(check, api.Sub(x, face4x), api.Sub(face4x, x))
	summand1 = api.Select(xIsNegative, api.Add(x, face4x), summand1)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(y, face4y), 1)) // Check if y > face4y?
	summand2 = api.Select(check, api.Sub(y, face4y), api.Sub(face4y, y))
	summand2 = api.Select(lngIsNegative, api.Add(y, face4y), summand2)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(z, face4z), 1)) // Check if z > face4x?
	summand3 = api.Select(check, api.Sub(z, face4z), api.Sub(face4z, z))
	summand3 = api.Select(latIsNegative, api.Add(z, face4z), summand3)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance4 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 4 is positive
	tmpArg1Negative4 := api.IsZero(api.Sub(api.Cmp(lng4, circuit.Lng), 1)) // Check if face's lng > lng?
	lngPos = api.Select(tmpArg1Negative4, api.Sub(lng4, circuit.Lng), api.Sub(circuit.Lng, lng4))
	diff4 := api.Select(lngIsNegative, api.Add(lng4, circuit.Lng), lngPos)
	tmpArg1Negative4 = api.Select(lngIsNegative, lngIsNegative, tmpArg1Negative4)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance4, sqDistance0), 1))
	sqDistance := api.Select(check, sqDistance0, sqDistance4) // Set sqDistance to lower value
	faceNum := api.Select(check, 0, 4)
	diff := api.Select(check, diff0, diff4)
	arg1Negative := api.Select(check, tmpArg1Negative, tmpArg1Negative4)
	// the constant values represent the cos() and sin() results of face 0 and face 4 latitudes
	// the sin() is positive for the latitudes of face 0 and face 4, cos() is always positive
	cosFaceLat := api.Select(check, 694132208, 881524236)
	sinFaceLat := api.Select(check, 719847538, 472138774)
	// azimuth radians
	azRadx := api.Select(check, 5619958268, 6130269123)

	// faces with negative x-coordinate and positive yz-coordinates:
	face1x := 213923483
	face1y := 147817182
	face1z := 965601793
	face5x := 105549814
	face5y := 979445729
	face5z := 171887461
	face6x := 807540757
	face6y := 153355248
	face6z := 569526199
	face10x := 740562147
	face10y := 667329956
	face10z := 78983764

	// Face 1
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(face1x, x), 1)) // Check if face1x > x?
	summand1 = api.Select(check, api.Sub(face1x, x), api.Sub(x, face1x))
	summand1 = api.Select(xIsNegative, summand1, api.Add(face1x, x))

	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(y, face1y), 1)) // Check if y > face1y?
	summand2 = api.Select(check, api.Sub(y, face1y), api.Sub(face1y, y))
	summand2 = api.Select(lngIsNegative, api.Add(y, face1y), summand2)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(z, face1z), 1)) // Check if z > face1z?
	summand3 = api.Select(check, api.Sub(z, face1z), api.Sub(face1z, z))
	summand3 = api.Select(latIsNegative, api.Add(z, face1z), summand3)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance1 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 1 is positive
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(lng1, circuit.Lng), 1)) // Check if face's lng > lng?
	lngPos = api.Select(tmpArg1Negative, api.Sub(lng1, circuit.Lng), api.Sub(circuit.Lng, lng1))
	diff1 := api.Select(lngIsNegative, api.Add(lng1, circuit.Lng), lngPos)
	tmpArg1Negative = api.Select(lngIsNegative, lngIsNegative, tmpArg1Negative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance1), 1))
	sqDistance = api.Select(check, sqDistance1, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 1, faceNum)
	diff = api.Select(check, diff1, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 1
	// the sin() is positive for the latitude of face 1, cos() is always positive
	cosFaceLat = api.Select(check, 260025338, cosFaceLat)
	sinFaceLat = api.Select(check, 965601794, sinFaceLat)
	// azimuth radians
	azRadx = api.Select(check, 5760339081, azRadx)

	// Face 5
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(face5x, x), 1)) // Check if face5x > x?
	summand1 = api.Select(check, api.Sub(face5x, x), api.Sub(x, face5x))
	summand1 = api.Select(xIsNegative, summand1, api.Add(face5x, x))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(y, face5y), 1)) // Check if y > face5y?
	summand2 = api.Select(check, api.Sub(y, face5y), api.Sub(face5y, y))
	summand2 = api.Select(lngIsNegative, api.Add(y, face5y), summand2)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(z, face5z), 1)) // Check if z > face5z?
	summand3 = api.Select(check, api.Sub(z, face5z), api.Sub(face5z, z))
	summand3 = api.Select(latIsNegative, api.Add(z, face5z), summand3)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance5 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 5 is positive
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(lng5, circuit.Lng), 1)) // Check if face's lng > lng?
	lngPos = api.Select(tmpArg1Negative, api.Sub(lng5, circuit.Lng), api.Sub(circuit.Lng, lng5))
	diff5 := api.Select(lngIsNegative, api.Add(lng5, circuit.Lng), lngPos)
	tmpArg1Negative = api.Select(lngIsNegative, lngIsNegative, tmpArg1Negative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance5), 1))
	sqDistance = api.Select(check, sqDistance5, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 5, faceNum)
	diff = api.Select(check, diff5, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 5
	// the sin() is positive for the latitude of face 5, cos() is always positive
	cosFaceLat = api.Select(check, 985116592, cosFaceLat)
	sinFaceLat = api.Select(check, 171887461, sinFaceLat)
	// azimuth radians
	azRadx = api.Select(check, 2692877706, azRadx)

	// Face 6
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(face6x, x), 1)) // Check if face6x > x?
	summand1 = api.Select(check, api.Sub(face6x, x), api.Sub(x, face6x))
	summand1 = api.Select(xIsNegative, summand1, api.Add(face6x, x))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(y, face6y), 1)) // Check if y > face6y?
	summand2 = api.Select(check, api.Sub(y, face6y), api.Sub(face6y, y))
	summand2 = api.Select(lngIsNegative, api.Add(y, face6y), summand2)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(z, face6z), 1)) // Check if z > face6z?
	summand3 = api.Select(check, api.Sub(z, face6z), api.Sub(face6z, z))
	summand3 = api.Select(latIsNegative, api.Add(z, face6z), summand3)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance6 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 6 is positive
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(lng6, circuit.Lng), 1)) // Check if face's lng > lng?
	lngPos = api.Select(tmpArg1Negative, api.Sub(lng6, circuit.Lng), api.Sub(circuit.Lng, lng6))
	diff6 := api.Select(lngIsNegative, api.Add(lng6, circuit.Lng), lngPos)
	tmpArg1Negative = api.Select(lngIsNegative, lngIsNegative, tmpArg1Negative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance6), 1))
	sqDistance = api.Select(check, sqDistance6, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 6, faceNum)
	diff = api.Select(check, diff6, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 6
	// the sin() is positive for the latitude of face 6, cos() is always positive
	cosFaceLat = api.Select(check, 821973180, cosFaceLat)
	sinFaceLat = api.Select(check, 569526199, sinFaceLat)
	// azimuth radians
	azRadx = api.Select(check, 2982963003, azRadx)

	// Face 10
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(face10x, x), 1)) // Check if face10x > x?
	summand1 = api.Select(check, api.Sub(face10x, x), api.Sub(x, face10x))
	summand1 = api.Select(xIsNegative, summand1, api.Add(face10x, x))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(y, face10y), 1)) // Check if y > face10y?
	summand2 = api.Select(check, api.Sub(y, face10y), api.Sub(face10y, y))
	summand2 = api.Select(lngIsNegative, api.Add(y, face10y), summand2)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(z, face10z), 1)) // Check if z > face10z?
	summand3 = api.Select(check, api.Sub(z, face10z), api.Sub(face10z, z))
	summand3 = api.Select(latIsNegative, api.Add(z, face10z), summand3)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance10 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 10 is positive
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(lng10, circuit.Lng), 1)) // Check if face's lng > lng?
	lngPos = api.Select(tmpArg1Negative, api.Sub(lng10, circuit.Lng), api.Sub(circuit.Lng, lng10))
	diff10 := api.Select(lngIsNegative, api.Add(lng10, circuit.Lng), lngPos)
	tmpArg1Negative = api.Select(lngIsNegative, lngIsNegative, tmpArg1Negative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance10), 1))
	sqDistance = api.Select(check, sqDistance10, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 10, faceNum)
	diff = api.Select(check, diff10, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 10
	// the sin() is positive for the latitude of face 10, cos() is always positive
	cosFaceLat = api.Select(check, 996875902, cosFaceLat)
	sinFaceLat = api.Select(check, 78983765, sinFaceLat)
	// azimuth radians
	azRadx = api.Select(check, 5930472956, azRadx)

	// faces with negative y-coordinate and positive xz-coordinates:
	face2x := 109262527
	face2y := 481195157
	face2z := 869777512
	face3x := 742856730
	face3y := 359394167
	face3z := 564800593

	// Face 2
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(x, face2x), 1)) // Check if x > face2x?
	summand1 = api.Select(check, api.Sub(x, face2x), api.Sub(face2x, x))
	summand1 = api.Select(xIsNegative, api.Add(x, face2x), summand1)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face2y, y), 1)) // Check if face2y > y?
	summand2 = api.Select(check, api.Sub(face2y, y), api.Sub(y, face2y))
	summand2 = api.Select(lngIsNegative, summand2, api.Add(face2y, y))

	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(z, face2z), 1)) // Check if z > face2z?
	summand3 = api.Select(check, api.Sub(z, face2z), api.Sub(face2z, z))
	summand3 = api.Select(latIsNegative, api.Add(z, face2z), summand3)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance2 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 2 is negative
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(circuit.Lng, lng2), 1)) // Check if lng > face's lng?
	distinguish := api.Select(tmpArg1Negative, api.Sub(circuit.Lng, lng2), api.Sub(lng2, circuit.Lng))
	diff2 := api.Select(lngIsNegative, distinguish, api.Add(lng2, circuit.Lng))
	tmpArg1Negative = api.Select(lngIsNegative, tmpArg1Negative, lngIsNegative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance2), 1))
	sqDistance = api.Select(check, sqDistance2, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 2, faceNum)
	diff = api.Select(check, diff2, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 2
	// the sin() is positive for the latitude of face 2, cos() is always positive
	cosFaceLat = api.Select(check, 493444100, cosFaceLat)
	sinFaceLat = api.Select(check, 869777512, sinFaceLat)
	// azimuth radians
	azRadx = api.Select(check, 780213654, azRadx)

	// Face 3
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(x, face3x), 1)) // Check if x > face3x?
	summand1 = api.Select(check, api.Sub(x, face3x), api.Sub(face3x, x))
	summand1 = api.Select(xIsNegative, api.Add(x, face3x), summand1)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face3y, y), 1)) // Check if face3y > y?
	summand2 = api.Select(check, api.Sub(face3y, y), api.Sub(y, face3y))
	summand2 = api.Select(lngIsNegative, summand2, api.Add(face3y, y))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}

	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(z, face3z), 1)) // Check if z > face3z?
	summand3 = api.Select(check, api.Sub(z, face3z), api.Sub(face3z, z))
	summand3 = api.Select(latIsNegative, api.Add(z, face3z), summand3)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance3 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 3 is negative
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(circuit.Lng, lng3), 1)) // Check if lng > face's lng?
	distinguish = api.Select(tmpArg1Negative, api.Sub(circuit.Lng, lng3), api.Sub(lng3, circuit.Lng))
	diff3 := api.Select(lngIsNegative, distinguish, api.Add(lng3, circuit.Lng))
	tmpArg1Negative = api.Select(lngIsNegative, tmpArg1Negative, lngIsNegative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance3), 1))
	sqDistance = api.Select(check, sqDistance3, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 3, faceNum)
	diff = api.Select(check, diff3, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 3
	// the sin() is positive for the latitude of face 3, cos() is always positive
	cosFaceLat = api.Select(check, 825227417, cosFaceLat)
	sinFaceLat = api.Select(check, 564800594, sinFaceLat)
	// azimuth radians
	azRadx = api.Select(check, 430469363, azRadx)

	// faces with negative z-coordinate and positive xy-coordinates:
	face9x := 851230398
	face9y := 472234378
	face9z := 228913738
	face14x := 284614806
	face14y := 864408097
	face14z := 414479255

	// Face 9
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(x, face9x), 1)) // Check if x > face9x?
	summand1 = api.Select(check, api.Sub(x, face9x), api.Sub(face9x, x))
	summand1 = api.Select(xIsNegative, api.Add(x, face9x), summand1)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(y, face9y), 1)) // Check if y > face9y?
	summand2 = api.Select(check, api.Sub(y, face9y), api.Sub(face9y, y))
	summand2 = api.Select(lngIsNegative, api.Add(y, face9y), summand2)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face9z, z), 1)) // Check if face9z > z?
	summand3 = api.Select(check, api.Sub(face9z, z), api.Sub(z, face9z))
	summand3 = api.Select(latIsNegative, summand3, api.Add(face9z, z))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance9 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 9 is positive
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(lng9, circuit.Lng), 1)) // Check if face's lng > lng?
	lngPos = api.Select(tmpArg1Negative, api.Sub(lng9, circuit.Lng), api.Sub(circuit.Lng, lng9))
	diff9 := api.Select(lngIsNegative, api.Add(lng9, circuit.Lng), lngPos)
	tmpArg1Negative = api.Select(lngIsNegative, lngIsNegative, tmpArg1Negative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance9), 1))
	sqDistance = api.Select(check, sqDistance9, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 9, faceNum)
	diff = api.Select(check, diff9, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 9
	// the sin() is negative for the latitude of face 9, cos() is always positive
	cosFaceLat = api.Select(check, 973446712, cosFaceLat)
	sinFaceLat = api.Select(check, 228913739, sinFaceLat)
	sinFaceLatNegative := api.Select(check, 1, 0)
	// azimuth radians
	azRadx = api.Select(check, 3003214169, azRadx)

	// Face 14
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(x, face14x), 1)) // Check if x > face14x?
	summand1 = api.Select(check, api.Sub(x, face14x), api.Sub(face14x, x))
	summand1 = api.Select(xIsNegative, api.Add(x, face14x), summand1)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(y, face14y), 1)) // Check if y > face14y?
	summand2 = api.Select(check, api.Sub(y, face14y), api.Sub(face14y, y))
	summand2 = api.Select(lngIsNegative, api.Add(y, face14y), summand2)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face14z, z), 1)) // Check if face14z > z?
	summand3 = api.Select(check, api.Sub(face14z, z), api.Sub(z, face14z))
	summand3 = api.Select(latIsNegative, summand3, api.Add(face14z, z))

	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance14 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 14 is positive
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(lng14, circuit.Lng), 1)) // Check if face's lng > lng?
	lngPos = api.Select(tmpArg1Negative, api.Sub(lng14, circuit.Lng), api.Sub(circuit.Lng, lng14))
	diff14 := api.Select(lngIsNegative, api.Add(lng14, circuit.Lng), lngPos)
	tmpArg1Negative = api.Select(lngIsNegative, lngIsNegative, tmpArg1Negative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance14), 1))
	sqDistance = api.Select(check, sqDistance14, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 14, faceNum)
	diff = api.Select(check, diff14, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 14
	// the sin() is negative for the latitude of face 14, cos() is always positive
	cosFaceLat = api.Select(check, 910058760, cosFaceLat)
	sinFaceLat = api.Select(check, 414479255, sinFaceLat)
	sinFaceLatNegative = api.Select(check, 1, sinFaceLatNegative)
	// azimuth radians
	azRadx = api.Select(check, 5891865957, azRadx)

	// faces with negative xy-coordinates and positive z-coordinate:
	face7x := 284614806
	face7y := 864408097
	face7z := 414479255
	face11x := 851230398
	face11y := 472234378
	face11z := 228913738

	// Face 7
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(face7x, x), 1)) // Check if face7x > x?
	summand1 = api.Select(check, api.Sub(face7x, x), api.Sub(x, face7x))
	summand1 = api.Select(xIsNegative, summand1, api.Add(face7x, x))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}

	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face7y, y), 1)) // Check if face7y > y?
	summand2 = api.Select(check, api.Sub(face7y, y), api.Sub(y, face7y))
	summand2 = api.Select(lngIsNegative, summand2, api.Add(face7y, y))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}

	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(z, face7z), 1)) // Check if z > face7z?
	summand3 = api.Select(check, api.Sub(z, face7z), api.Sub(face7z, z))
	summand3 = api.Select(latIsNegative, api.Add(z, face7z), summand3)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance7 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 7 is negative
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(circuit.Lng, lng7), 1)) // Check if lng > face's lng?
	distinguish = api.Select(tmpArg1Negative, api.Sub(circuit.Lng, lng7), api.Sub(lng7, circuit.Lng))
	diff7 := api.Select(lngIsNegative, distinguish, api.Add(lng7, circuit.Lng))
	tmpArg1Negative = api.Select(lngIsNegative, tmpArg1Negative, lngIsNegative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance7), 1))
	sqDistance = api.Select(check, sqDistance7, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 7, faceNum)
	diff = api.Select(check, diff7, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 7
	// the sin() is positive for the latitude of face 7, cos() is always positive
	cosFaceLat = api.Select(check, 910058760, cosFaceLat)
	sinFaceLat = api.Select(check, 414479255, sinFaceLat)
	sinFaceLatNegative = api.Select(check, 0, sinFaceLatNegative)
	// azimuth radians
	azRadx = api.Select(check, 3532912002, azRadx)

	// Face 11
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(face11x, x), 1)) // Check if face11x > x?
	summand1 = api.Select(check, api.Sub(face11x, x), api.Sub(x, face11x))
	summand1 = api.Select(xIsNegative, summand1, api.Add(face11x, x))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face11y, y), 1)) // Check if face11y > y?
	summand2 = api.Select(check, api.Sub(face11y, y), api.Sub(y, face11y))
	summand2 = api.Select(lngIsNegative, summand2, api.Add(face11y, y))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(z, face11z), 1)) // Check if z > face11z?
	summand3 = api.Select(check, api.Sub(z, face11z), api.Sub(face11z, z))
	summand3 = api.Select(latIsNegative, api.Add(z, face11z), summand3)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance11 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 11 is negative
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(circuit.Lng, lng11), 1)) // Check if lng > face's lng?
	distinguish = api.Select(tmpArg1Negative, api.Sub(circuit.Lng, lng11), api.Sub(lng11, circuit.Lng))
	diff11 := api.Select(lngIsNegative, distinguish, api.Add(lng11, circuit.Lng))
	tmpArg1Negative = api.Select(lngIsNegative, tmpArg1Negative, lngIsNegative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance11), 1))
	sqDistance = api.Select(check, sqDistance11, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 11, faceNum)
	diff = api.Select(check, diff11, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 11
	// the sin() is positive for the latitude of face 11, cos() is always positive
	cosFaceLat = api.Select(check, 973446712, cosFaceLat)
	sinFaceLat = api.Select(check, 228913739, sinFaceLat)
	sinFaceLatNegative = api.Select(check, 0, sinFaceLatNegative)
	// azimuth radians
	azRadx = api.Select(check, 138378484, azRadx)

	// faces with negative xz-coordinates and positive y-coordinate:
	face15x := 742856730
	face15y := 359394167
	face15z := 564800593
	face19x := 109262527
	face19y := 481195157
	face19z := 869777512

	// Face 15
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(face15x, x), 1)) // Check if face15x > x?
	summand1 = api.Select(check, api.Sub(face15x, x), api.Sub(x, face15x))
	summand1 = api.Select(xIsNegative, summand1, api.Add(face15x, x))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(y, face15y), 1)) // Check if y > face15y?
	summand2 = api.Select(check, api.Sub(y, face15y), api.Sub(face15y, y))
	summand2 = api.Select(lngIsNegative, api.Add(y, face15y), summand2)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face15z, z), 1)) // Check if face15z > z?
	summand3 = api.Select(check, api.Sub(face15z, z), api.Sub(z, face15z))
	summand3 = api.Select(latIsNegative, summand3, api.Add(face15z, z))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance15 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 15 is positive
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(lng15, circuit.Lng), 1)) // Check if face's lng > lng?
	lngPos = api.Select(tmpArg1Negative, api.Sub(lng15, circuit.Lng), api.Sub(circuit.Lng, lng15))
	diff15 := api.Select(lngIsNegative, api.Add(lng15, circuit.Lng), lngPos)
	tmpArg1Negative = api.Select(lngIsNegative, lngIsNegative, tmpArg1Negative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance15), 1))
	sqDistance = api.Select(check, sqDistance15, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 15, faceNum)
	diff = api.Select(check, diff15, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 15
	// the sin() is negative for the latitude of face 15, cos() is always positive
	cosFaceLat = api.Select(check, 825227417, cosFaceLat)
	sinFaceLat = api.Select(check, 564800594, sinFaceLat)
	sinFaceLatNegative = api.Select(check, 1, sinFaceLatNegative)
	// azimuth radians
	azRadx = api.Select(check, 2711123289, azRadx)

	// Face 19
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(face19x, x), 1)) // Check if face19x > x?
	summand1 = api.Select(check, api.Sub(face19x, x), api.Sub(x, face19x))
	summand1 = api.Select(xIsNegative, summand1, api.Add(face19x, x))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(y, face19y), 1)) // Check if y > face19y?
	summand2 = api.Select(check, api.Sub(y, face19y), api.Sub(face19y, y))
	summand2 = api.Select(lngIsNegative, api.Add(y, face19y), summand2)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face19z, z), 1)) // Check if face19z > z?
	summand3 = api.Select(check, api.Sub(face19z, z), api.Sub(z, face19z))
	summand3 = api.Select(latIsNegative, summand3, api.Add(face19z, z))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance19 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 19 is positive
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(lng19, circuit.Lng), 1)) // Check if face's lng > lng?
	lngPos = api.Select(tmpArg1Negative, api.Sub(lng19, circuit.Lng), api.Sub(circuit.Lng, lng19))
	diff19 := api.Select(lngIsNegative, api.Add(lng19, circuit.Lng), lngPos)
	tmpArg1Negative = api.Select(lngIsNegative, lngIsNegative, tmpArg1Negative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance19), 1))
	sqDistance = api.Select(check, sqDistance19, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 19, faceNum)
	diff = api.Select(check, diff19, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 19
	// the sin() is negative for the latitude of face 19, cos() is always positive
	cosFaceLat = api.Select(check, 493444100, cosFaceLat)
	sinFaceLat = api.Select(check, 869777512, sinFaceLat)
	sinFaceLatNegative = api.Select(check, 1, sinFaceLatNegative)
	// azimuth radians
	azRadx = api.Select(check, 2361378999, azRadx)

	// faces with negative yz-coordinates and positive x-coordinate:
	face8x := 740562147
	face8y := 667329956
	face8z := 78983764
	face12x := 105549814
	face12y := 979445729
	face12z := 171887461
	face13x := 807540757
	face13y := 153355248
	face13z := 569526199
	face18x := 213923483
	face18y := 147817182
	face18z := 965601793

	// Face 8
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(x, face8x), 1)) // Check if x > face8x?
	summand1 = api.Select(check, api.Sub(x, face8x), api.Sub(face8x, x))
	summand1 = api.Select(xIsNegative, api.Add(x, face8x), summand1)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face8y, y), 1)) // Check if face8y > y?
	summand2 = api.Select(check, api.Sub(face8y, y), api.Sub(y, face8y))
	summand2 = api.Select(lngIsNegative, summand2, api.Add(face8y, y))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face8z, z), 1)) // Check if face8z > z?
	summand3 = api.Select(check, api.Sub(face8z, z), api.Sub(z, face8z))
	summand3 = api.Select(latIsNegative, summand3, api.Add(face8z, z))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance8 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 8 is negative
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(circuit.Lng, lng8), 1)) // Check if lng > face's lng?
	distinguish = api.Select(tmpArg1Negative, api.Sub(circuit.Lng, lng8), api.Sub(lng8, circuit.Lng))
	diff8 := api.Select(lngIsNegative, distinguish, api.Add(lng8, circuit.Lng))
	tmpArg1Negative = api.Select(lngIsNegative, tmpArg1Negative, lngIsNegative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance8), 1))
	sqDistance = api.Select(check, sqDistance8, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 8, faceNum)
	diff = api.Select(check, diff8, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 8
	// the sin() is negative for the latitude of face 8, cos() is always positive
	cosFaceLat = api.Select(check, 996875902, cosFaceLat)
	sinFaceLat = api.Select(check, 78983765, sinFaceLat)
	sinFaceLatNegative = api.Select(check, 1, sinFaceLatNegative)
	// azimuth radians
	azRadx = api.Select(check, 3494305004, azRadx)

	// Face 12
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(x, face12x), 1)) // Check if x > face12x?
	summand1 = api.Select(check, api.Sub(x, face12x), api.Sub(face12x, x))
	summand1 = api.Select(xIsNegative, api.Add(x, face12x), summand1)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face12y, y), 1)) // Check if face12y > y?
	summand2 = api.Select(check, api.Sub(face12y, y), api.Sub(y, face12y))
	summand2 = api.Select(lngIsNegative, summand2, api.Add(face12y, y))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face12z, z), 1)) // Check if face12z > z?
	summand3 = api.Select(check, api.Sub(face12z, z), api.Sub(z, face12z))
	summand3 = api.Select(latIsNegative, summand3, api.Add(face12z, z))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance12 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 12 is negative
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(circuit.Lng, lng12), 1)) // Check if lng > face's lng?
	distinguish = api.Select(tmpArg1Negative, api.Sub(circuit.Lng, lng12), api.Sub(lng12, circuit.Lng))
	diff12 := api.Select(lngIsNegative, distinguish, api.Add(lng12, circuit.Lng))
	tmpArg1Negative = api.Select(lngIsNegative, tmpArg1Negative, lngIsNegative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance12), 1))
	sqDistance = api.Select(check, sqDistance12, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 12, faceNum)
	diff = api.Select(check, diff12, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 12
	// the sin() is negative for the latitude of face 12, cos() is always positive
	cosFaceLat = api.Select(check, 985116592, cosFaceLat)
	sinFaceLat = api.Select(check, 171887461, sinFaceLat)
	sinFaceLatNegative = api.Select(check, 1, sinFaceLatNegative)
	// azimuth radians
	azRadx = api.Select(check, 448714947, azRadx)

	// Face 13
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(x, face13x), 1)) // Check if x > face13x?
	summand1 = api.Select(check, api.Sub(x, face13x), api.Sub(face13x, x))
	summand1 = api.Select(xIsNegative, api.Add(x, face13x), summand1)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face13y, y), 1)) // Check if face13y > y?
	summand2 = api.Select(check, api.Sub(face13y, y), api.Sub(y, face13y))
	summand2 = api.Select(lngIsNegative, summand2, api.Add(face13y, y))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face13z, z), 1)) // Check if face13z > z?
	summand3 = api.Select(check, api.Sub(face13z, z), api.Sub(z, face13z))
	summand3 = api.Select(latIsNegative, summand3, api.Add(face13z, z))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance13 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 13 is negative
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(circuit.Lng, lng13), 1)) // Check if lng > face's lng?
	distinguish = api.Select(tmpArg1Negative, api.Sub(circuit.Lng, lng13), api.Sub(lng13, circuit.Lng))
	diff13 := api.Select(lngIsNegative, distinguish, api.Add(lng13, circuit.Lng))
	tmpArg1Negative = api.Select(lngIsNegative, tmpArg1Negative, lngIsNegative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance13), 1))
	sqDistance = api.Select(check, sqDistance13, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 13, faceNum)
	diff = api.Select(check, diff13, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 13
	// the sin() is negative for the latitude of face 13, cos() is always positive
	cosFaceLat = api.Select(check, 821973180, cosFaceLat)
	sinFaceLat = api.Select(check, 569526199, sinFaceLat)
	sinFaceLatNegative = api.Select(check, 1, sinFaceLatNegative)
	// azimuth radians
	azRadx = api.Select(check, 158629650, azRadx)

	// Face 18
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(x, face18x), 1)) // Check if x > face18x?
	summand1 = api.Select(check, api.Sub(x, face18x), api.Sub(face18x, x))
	summand1 = api.Select(xIsNegative, api.Add(x, face18x), summand1)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face18y, y), 1)) // Check if face18y > y?
	summand2 = api.Select(check, api.Sub(face18y, y), api.Sub(y, face18y))
	summand2 = api.Select(lngIsNegative, summand2, api.Add(face18y, y))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face18z, z), 1)) // Check if face18z > z?
	summand3 = api.Select(check, api.Sub(face18z, z), api.Sub(z, face18z))
	summand3 = api.Select(latIsNegative, summand3, api.Add(face18z, z))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance18 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 18 is negative
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(circuit.Lng, lng18), 1)) // Check if lng > face's lng?
	distinguish = api.Select(tmpArg1Negative, api.Sub(circuit.Lng, lng18), api.Sub(lng18, circuit.Lng))
	diff18 := api.Select(lngIsNegative, distinguish, api.Add(lng18, circuit.Lng))
	tmpArg1Negative = api.Select(lngIsNegative, tmpArg1Negative, lngIsNegative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance18), 1))
	sqDistance = api.Select(check, sqDistance18, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 18, faceNum)
	diff = api.Select(check, diff18, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 18
	// the sin() is negative for the latitude of face 18, cos() is always positive
	cosFaceLat = api.Select(check, 260025338, cosFaceLat)
	sinFaceLat = api.Select(check, 965601794, sinFaceLat)
	sinFaceLatNegative = api.Select(check, 1, sinFaceLatNegative)
	// azimuth radians
	azRadx = api.Select(check, 3664438879, azRadx)

	// faces with only negative xyz-coordinates:
	face16x := 811253470
	face16y := 344895323
	face16z := 472138773
	face17x := 219930779
	face17y := 658369178
	face17z := 719847537

	// Face 16
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(face16x, x), 1)) // Check if face16x > x?
	summand1 = api.Select(check, api.Sub(face16x, x), api.Sub(x, face16x))
	summand1 = api.Select(xIsNegative, summand1, api.Add(face16x, x))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face16y, y), 1)) // Check if face16y > y?
	summand2 = api.Select(check, api.Sub(face16y, y), api.Sub(y, face16y))
	summand2 = api.Select(lngIsNegative, summand2, api.Add(face16y, y))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face16z, z), 1)) // Check if face16z > z?
	summand3 = api.Select(check, api.Sub(face16z, z), api.Sub(z, face16z))
	summand3 = api.Select(latIsNegative, summand3, api.Add(face16z, z))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance16 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 16 is negative
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(circuit.Lng, lng16), 1)) // Check if lng > face's lng?
	distinguish = api.Select(tmpArg1Negative, api.Sub(circuit.Lng, lng16), api.Sub(lng16, circuit.Lng))
	diff16 := api.Select(lngIsNegative, distinguish, api.Add(lng16, circuit.Lng))
	tmpArg1Negative = api.Select(lngIsNegative, tmpArg1Negative, lngIsNegative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance16), 1))
	sqDistance = api.Select(check, sqDistance16, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 16, faceNum)
	diff = api.Select(check, diff16, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 16
	// the sin() is negative for the latitude of face 16, cos() is always positive
	cosFaceLat = api.Select(check, 881524236, cosFaceLat)
	sinFaceLat = api.Select(check, 472138774, sinFaceLat)
	sinFaceLatNegative = api.Select(check, 1, sinFaceLatNegative)
	// azimuth radians
	azRadx = api.Select(check, 3294508837, azRadx)

	// Face 17
	// Calculate square distance to face center considering + and -
	check = api.IsZero(api.Sub(api.Cmp(face17x, x), 1)) // Check if face17x > x?
	summand1 = api.Select(check, api.Sub(face17x, x), api.Sub(x, face17x))
	summand1 = api.Select(xIsNegative, summand1, api.Add(face17x, x))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand1, summand1), 1000000000)
	if err != nil {
		panic(err)
	}
	summand1 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face17y, y), 1)) // Check if face17y > y?
	summand2 = api.Select(check, api.Sub(face17y, y), api.Sub(y, face17y))
	summand2 = api.Select(lngIsNegative, summand2, api.Add(face17y, y))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand2, summand2), 1000000000)
	if err != nil {
		panic(err)
	}
	summand2 = result[0]

	check = api.IsZero(api.Sub(api.Cmp(face17z, z), 1)) // Check if face17z > z?
	summand3 = api.Select(check, api.Sub(face17z, z), api.Sub(z, face17z))
	summand3 = api.Select(latIsNegative, summand3, api.Add(face17z, z))
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(summand3, summand3), 1000000000)
	if err != nil {
		panic(err)
	}
	summand3 = result[0]

	sqDistance17 := api.Add(api.Add(summand1, summand2), summand3)

	// Longitude of face center subtracted from coordinate's longitude for azimuth
	// Longitude of face 17 is negative
	tmpArg1Negative = api.IsZero(api.Sub(api.Cmp(circuit.Lng, lng17), 1)) // Check if lng > face's lng?
	distinguish = api.Select(tmpArg1Negative, api.Sub(circuit.Lng, lng17), api.Sub(lng17, circuit.Lng))
	diff17 := api.Select(lngIsNegative, distinguish, api.Add(lng17, circuit.Lng))
	tmpArg1Negative = api.Select(lngIsNegative, tmpArg1Negative, lngIsNegative)

	check = api.IsZero(api.Sub(api.Cmp(sqDistance, sqDistance17), 1))
	sqDistance = api.Select(check, sqDistance17, sqDistance) // Set sqDistance to lower value
	faceNum = api.Select(check, 17, faceNum)
	diff = api.Select(check, diff17, diff)
	arg1Negative = api.Select(check, tmpArg1Negative, arg1Negative)
	// the constant values represent the cos() and sin() results for the latitude of face 17
	// the sin() is negative for the latitude of face 17, cos() is always positive
	cosFaceLat = api.Select(check, 694132208, cosFaceLat)
	sinFaceLat = api.Select(check, 719847538, sinFaceLat)
	sinFaceLatNegative = api.Select(check, 1, sinFaceLatNegative)
	// azimuth radians
	azRadx = api.Select(check, 3804819692, azRadx)

	// Starting calculation of atan2() and necessary inputs
	greaterPi := api.IsZero(api.Sub(api.Cmp(diff, pi), 1)) // Check if diff > pi?
	term = api.Select(greaterPi, api.Sub(diff, pi), diff)
	arg1Negative = api.Select(greaterPi, api.Sub(1, arg1Negative), arg1Negative)
	sinDiff := math.Sine(api, term) // sin(Lng2 - Lng1)         frontend.Variable(12330365)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(cosLat, sinDiff), 1000000000)
	if err != nil {
		panic(err)
	}
	arg1 := result[0] // 10^9-based result

	threeHalfsPi := api.Add(halfPi, pi)
	greaterHalfPi := api.IsZero(api.Sub(api.Cmp(diff, halfPi), 1))         // Check if diff > pi/2?
	greater3HalfsPi := api.IsZero(api.Sub(api.Cmp(diff, threeHalfsPi), 1)) // Check if diff > 1.5pi?
	cosDiffIsNegative := api.Select(greaterHalfPi, api.Sub(1, greater3HalfsPi), 0)
	term = api.Select(cosDiffIsNegative, api.Sub(diff, halfPi), api.Add(diff, halfPi))
	term = api.Select(greater3HalfsPi, api.Sub(diff, threeHalfsPi), term)
	cosDiff := math.Sine(api, term) // cos(Lng2 - Lng1)

	// The z value and the sin(lat) are equal, the sign of lat therefore determines the sign of arg2Part1
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(cosFaceLat, z), 1000000000)
	if err != nil {
		panic(err)
	}
	arg2Part1 := result[0] // 10^9-based result

	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(api.Mul(sinFaceLat, cosLat), cosDiff), 1000000000000000000)
	if err != nil {
		panic(err)
	}
	arg2Part2 := result[0] // 10^9-based result

	arg2Part2Negative := api.Select(sinFaceLatNegative,
		api.Sub(1, cosDiffIsNegative), cosDiffIsNegative)

	p1Larger := api.IsZero(api.Sub(api.Cmp(arg2Part1, arg2Part2), 1)) // Check if part1 > part2?
	arg2Negative := api.Select(latIsNegative, api.Select(arg2Part2Negative, p1Larger, 1),
		api.Select(arg2Part2Negative, 0, api.Sub(1, p1Larger)))

	pos1pos2 := api.Select(p1Larger, api.Sub(arg2Part1, arg2Part2), api.Sub(arg2Part2, arg2Part1))
	neg1neg2 := api.Select(p1Larger, api.Sub(arg2Part1, arg2Part2), api.Sub(arg2Part2, arg2Part1))
	sum := api.Add(arg2Part1, arg2Part2)
	arg2 := api.Select(latIsNegative, api.Select(arg2Part2Negative, neg1neg2, sum),
		api.Select(arg2Part2Negative, sum, pos1pos2))

	// Calculate atan2(x,y)
	atan2Result := math.Atan2(api, arg1, arg2, arg1Negative, arg2Negative)
	atan2Negative := atan2Result[0]
	atan2 := atan2Result[1] //frontend.Variable(3106128240)

	// Applying _posAngleRads
	adjusted := api.Select(atan2Negative, api.Sub(doublePi, atan2), atan2)
	adjusted = api.Select(api.IsZero(api.Sub(api.Cmp(adjusted, doublePi), 1)),
		api.Sub(adjusted, doublePi), adjusted)

	// Subtracting adjusted result from azimuth radians to obtain theta
	check = api.IsZero(api.Sub(api.Cmp(adjusted, azRadx), 1)) // Check if adjusted > azRadx?
	tmp := api.Select(check, api.Sub(adjusted, azRadx), api.Sub(azRadx, adjusted))
	// Applying _posAngleRads
	theta := api.Select(check, api.Sub(doublePi, tmp), tmp)
	theta = api.Select(api.IsZero(api.Sub(api.Cmp(theta, doublePi), 1)), api.Sub(theta, doublePi), theta)

	//if odd resolution subtract aperture7:
	check = api.IsZero(api.Sub(api.Cmp(333473172, theta), 1)) // Check if aperture7 > theta?
	tmp = api.Select(check, api.Sub(333473172, theta), api.Sub(theta, 333473172))
	// Applying _posAngleRads
	thetaOddResolution := api.Select(check, api.Sub(doublePi, tmp), tmp)
	thetaOddResolution = api.Select(api.IsZero(api.Sub(api.Cmp(thetaOddResolution, doublePi), 1)),
		api.Sub(thetaOddResolution, doublePi), thetaOddResolution)

	checkr0 := api.IsZero(api.Cmp(resolution, 0))   // Check if resolution == 0?
	checkr1 := api.IsZero(api.Cmp(resolution, 1))   // Check if resolution == 1?
	checkr2 := api.IsZero(api.Cmp(resolution, 2))   // Check if resolution == 2?
	checkr3 := api.IsZero(api.Cmp(resolution, 3))   // Check if resolution == 3?
	checkr4 := api.IsZero(api.Cmp(resolution, 4))   // Check if resolution == 4?
	checkr5 := api.IsZero(api.Cmp(resolution, 5))   // Check if resolution == 5?
	checkr6 := api.IsZero(api.Cmp(resolution, 6))   // Check if resolution == 6?
	checkr7 := api.IsZero(api.Cmp(resolution, 7))   // Check if resolution == 7?
	checkr8 := api.IsZero(api.Cmp(resolution, 8))   // Check if resolution == 8?
	checkr9 := api.IsZero(api.Cmp(resolution, 9))   // Check if resolution == 9?
	checkr10 := api.IsZero(api.Cmp(resolution, 10)) // Check if resolution == 10?
	checkr11 := api.IsZero(api.Cmp(resolution, 11)) // Check if resolution == 11?
	checkr12 := api.IsZero(api.Cmp(resolution, 12)) // Check if resolution == 12?
	checkr13 := api.IsZero(api.Cmp(resolution, 13)) // Check if resolution == 13?
	checkr14 := api.IsZero(api.Cmp(resolution, 14)) // Check if resolution == 14?
	//checkr15 := api.IsZero(api.Cmp(resolution, 15)) // Check if resolution == 15?

	theta = api.Select(checkr0, theta,
		api.Select(checkr1, thetaOddResolution,
			api.Select(checkr2, theta,
				api.Select(checkr3, thetaOddResolution,
					api.Select(checkr4, theta,
						api.Select(checkr5, thetaOddResolution,
							api.Select(checkr6, theta,
								api.Select(checkr7, thetaOddResolution,
									api.Select(checkr8, theta,
										api.Select(checkr9, thetaOddResolution,
											api.Select(checkr10, theta,
												api.Select(checkr11, thetaOddResolution,
													api.Select(checkr12, theta,
														api.Select(checkr13, thetaOddResolution,
															api.Select(checkr14, theta, thetaOddResolution)))))))))))))))

	sinThetaNegative := api.IsZero(api.Sub(api.Cmp(theta, pi), 1)) // Check if theta > pi?
	sinArg := api.Select(sinThetaNegative, api.Sub(theta, pi), theta)

	cosArg := api.Add(theta, halfPi)
	cosArgPi := api.IsZero(api.Sub(api.Cmp(cosArg, pi), 1))        // Check if cosArg > pi?
	cosArg2Pi := api.IsZero(api.Sub(api.Cmp(cosArg, doublePi), 1)) // Check if cosArg > 2pi?
	cosThetaNegative := api.Select(cosArgPi, api.Sub(1, cosArg2Pi), 0)
	cosArg = api.Select(cosThetaNegative,
		api.Sub(cosArg, pi), api.Select(cosArg2Pi, api.Sub(cosArg, doublePi), cosArg))

	sinTheta := math.Sine(api, sinArg) // sin(theta) frontend.Variable(122854077)
	cosTheta := math.Sine(api, cosArg) // cos(theta) frontend.Variable(992424746)

	r := CalculateR(api, sqDistance) //frontend.Variable(624753518)

	res0 := api.Mul(r, 1000000000)
	res1 := api.Mul(r, 2645751311)
	res2 := api.Mul(r, 7000000000)
	res3 := api.Mul(r, 18520259177)
	res4 := api.Mul(r, 49000000000)
	res5 := api.Mul(r, 129641814242)
	res6 := api.Mul(r, 343000000000)
	res7 := api.Mul(r, 907492699695)
	res8 := api.Mul(r, 2401000000000)
	res9 := api.Mul(r, 6352448897866)
	res10 := api.Mul(r, 16807000000000)
	res11 := api.Mul(r, 44467142285063)
	res12 := api.Mul(r, 117649000000000)
	res13 := api.Mul(r, 311269995995438)
	res14 := api.Mul(r, 823543000000000)
	res15 := api.Mul(r, 2178889971968066)

	r = api.Select(checkr0, res0,
		api.Select(checkr1, res1,
			api.Select(checkr2, res2,
				api.Select(checkr3, res3,
					api.Select(checkr4, res4,
						api.Select(checkr5, res5,
							api.Select(checkr6, res6,
								api.Select(checkr7, res7,
									api.Select(checkr8, res8,
										api.Select(checkr9, res9,
											api.Select(checkr10, res10,
												api.Select(checkr11, res11,
													api.Select(checkr12, res12,
														api.Select(checkr13, res13,
															api.Select(checkr14, res14, res15)))))))))))))))

	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, r, 1000000000)
	if err != nil {
		panic(err)
	}
	r = result[0]

	y = api.Mul(r, sinTheta)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, y, 1000000000)
	if err != nil {
		panic(err)
	}
	y = result[0]

	x = api.Mul(r, cosTheta)
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, x, 1000000000)
	if err != nil {
		panic(err)
	}
	x = result[0]

	ijkResult := Hex2dToCoordIJK(api, x, y, sinThetaNegative, cosThetaNegative)

	i := api.Div(ijkResult[0], 1000000000)
	j := api.Div(ijkResult[1], 1000000000)
	k := api.Div(ijkResult[2], 1000000000)

	api.AssertIsEqual(circuit.I, i)
	api.AssertIsEqual(circuit.J, j)
	api.AssertIsEqual(circuit.K, k)
	return nil
}

func CalculateR(api frontend.API, sqDistance frontend.Variable) frontend.Variable {

	// Calculating r: In the original code the variable r is calculated from the square distance
	// by a series of computations, with the first step being "r = acos(1 - sqd/2)" and the second
	// step "r = tan(r)". Since acos(x) = atan(sqrt((1-x)^2) / x) the first two steps can be
	// summarized to r = tan( acos(1 - sqd/2) ) = tan( atan( sqrt( (1-(1-sqd/2))^2 ) / (1-sqd/2) ))
	// = sqrt( (1-(1-sqd/2))^2 ) / (1-sqd/2) = sqrt( (-1)*(sqd-4)*sqd ) / (2 - sqd)

	rNominator := api.Mul(api.Sub(4000000000, sqDistance), sqDistance) // sqDistance is never > 4
	result, err := api.Compiler().NewHint(hints.IntegerDivisionHint, 1, rNominator, 1000000000)
	if err != nil {
		panic(err)
	}
	rNominator = result[0]
	rDivisor := api.Sub(2000000000, sqDistance)

	rNominator = math.SqRoot(api, rNominator)

	// To stay in 10^9: rNominator/rDivisor * resolution_constant all in one step
	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(rNominator, 2618034066), rDivisor) //2618033989), rDivisor)
	if err != nil {
		panic(err)
	}
	r := result[0]

	return r
}

func Hex2dToCoordIJK(api frontend.API, x frontend.Variable, y frontend.Variable, sinThetaNegative frontend.Variable, cosThetaNegative frontend.Variable) [3]frontend.Variable {

	result, err := api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(y, 1000000000), 866025404)
	if err != nil {
		panic(err)
	}
	x2 := result[0]

	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(x2, 1000000000), 2000000000)
	if err != nil {
		panic(err)
	}
	x1 := api.Add(x, result[0])

	result, err = api.Compiler().NewHint(hints.ModuloHint, 1, x1, 1000000000)
	if err != nil {
		panic(err)
	}
	r1 := result[0]

	result, err = api.Compiler().NewHint(hints.ModuloHint, 1, x2, 1000000000)
	if err != nil {
		panic(err)
	}
	r2 := result[0]

	m1 := api.Sub(x1, r1)
	m2 := api.Sub(x2, r2)

	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(r1, 2000000000), 1000000000)
	if err != nil {
		panic(err)
	}
	doubleR1 := result[0]

	r1CaseA := api.IsZero(api.Sub(api.Cmp(499999999, r1), 1))  // Check if 1/2 >= r1?
	r1CaseA1 := api.IsZero(api.Sub(api.Cmp(333333332, r1), 1)) // Check if 1/3 >= r1?
	r1CaseB1 := api.IsZero(api.Sub(api.Cmp(666666666, r1), 1)) // Check if 2/3 >= r1
	// Check if r2 >= 1-r1?
	iCaseA2First := api.IsZero(api.Sub(api.Cmp(api.Add(r2, 1), api.Sub(1000000000, r1)), 1))
	// Check if 2*r1 >= r2?
	iCaseA2Second := api.IsZero(api.Sub(api.Cmp(api.Add(doubleR1, 1), r2), 1))
	// Check if r2 > 2*r1-1?
	iCaseB1First := api.IsZero(api.Sub(api.Cmp(r2, api.Sub(doubleR1, 1000000000)), 1))
	// Check if 1-r1 > r2?
	iCaseB1Second := api.IsZero(api.Sub(api.Cmp(api.Sub(1000000000, r1), r2), 1))

	iCoord := api.Select(r1CaseA,
		api.Select(r1CaseA1, m1,
			api.Select(iCaseA2First,
				api.Select(iCaseA2Second, api.Add(m1, 1000000000), m1), m1)),
		api.Select(r1CaseB1,
			api.Select(iCaseB1First, api.Select(iCaseB1Second, m1,
				api.Add(m1, 1000000000)),
				api.Add(m1, 1000000000)),
			api.Add(m1, 1000000000)))

	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1,
		api.Mul(api.Add(r1, 1000000000), 1000000000), 2000000000)
	if err != nil {
		panic(err)
	}
	valueAr2Condition := api.Add(result[0], 1) // Add 1*10^(-9) to make > to >= later on

	result, err = api.Compiler().NewHint(hints.IntegerDivisionHint, 1, api.Mul(r1, 1000000000), 2000000000)
	if err != nil {
		panic(err)
	}
	valueBr2Condition := api.Add(result[0], 1) // Add 1*10^(-9) to make > to >= later on

	jCoordCaseA := api.Select(r1CaseA1,
		api.Select(api.IsZero(api.Sub(api.Cmp(valueAr2Condition, r2), 1)), m2, api.Add(m2, 1000000000)), api.Select(api.IsZero(api.Sub(api.Cmp(api.Sub(1000000001, r1), r2), 1)), m2, api.Add(m2, 1000000000)))
	jCoordCaseB := api.Select(r1CaseB1,
		api.Select(api.IsZero(api.Sub(api.Cmp(api.Sub(1000000001, r1), r2), 1)),
			m2, api.Add(m2, 1000000000)),
		api.Select(api.IsZero(api.Sub(api.Cmp(valueBr2Condition, r2), 1)),
			m2, api.Add(m2, 1000000000)))
	jCoord := api.Select(r1CaseA, jCoordCaseA, jCoordCaseB)

	iGreater := api.IsZero(api.Sub(api.Cmp(iCoord, jCoord), 1)) // Check if i > j?
	// In case only x is negative: i = -i + j
	// in case only y is negative: i = i - j
	// in case x AND y negative: i = -i
	iCoordNegative := api.Select(cosThetaNegative,
		api.Select(sinThetaNegative, 1, iGreater),
		api.Select(sinThetaNegative, api.Sub(1, iGreater), 0))
	iCoord = api.Select(cosThetaNegative,
		api.Select(sinThetaNegative, iCoord,
			api.Select(iGreater, api.Sub(iCoord, jCoord), api.Sub(jCoord, iCoord))),
		api.Select(sinThetaNegative,
			api.Select(iGreater, api.Sub(iCoord, jCoord), api.Sub(jCoord, iCoord)),
			iCoord))

	return NormalizeIJK(api, iCoord, iCoordNegative, jCoord, sinThetaNegative, 0, 0)
}

func NormalizeIJK(api frontend.API, iCoord frontend.Variable, iCoordNegative frontend.Variable, jCoord frontend.Variable, jCoordNegative frontend.Variable, kCoord frontend.Variable, kCoordNegative frontend.Variable) [3]frontend.Variable {

	var coordinates [3]frontend.Variable

	iGreaterj := api.IsZero(api.Sub(api.Cmp(iCoord, jCoord), 1)) // Check if i > j?
	jTmp := api.Select(jCoordNegative,
		api.Select(iGreaterj, api.Sub(iCoord, jCoord), api.Sub(jCoord, iCoord)),
		api.Add(iCoord, jCoord))
	jTmpNegative := api.Select(jCoordNegative, api.Sub(1, iGreaterj), 0)
	iGreaterk := api.IsZero(api.Sub(api.Cmp(iCoord, kCoord), 1)) // Check if i > k?
	kTmp := api.Select(kCoordNegative,
		api.Select(iGreaterk, api.Sub(iCoord, kCoord), api.Sub(kCoord, iCoord)),
		api.Add(iCoord, kCoord))
	kTmpNegative := api.Select(kCoordNegative, api.Sub(1, iGreaterk), 0)

	// if i < 0
	iCoord = api.Select(iCoordNegative, 0, iCoord)
	jCoord = api.Select(iCoordNegative, jTmp, jCoord)
	jCoordNegative = api.Select(iCoordNegative, jTmpNegative, jCoordNegative)
	kCoord = api.Select(iCoordNegative, kTmp, kCoord)
	kCoordNegative = api.Select(iCoordNegative, kTmpNegative, kCoordNegative)

	jGreaterk := api.IsZero(api.Sub(api.Cmp(jCoord, kCoord), 1)) // Check if j > k?
	kTmp = api.Select(kCoordNegative,
		api.Select(jGreaterk, api.Sub(jCoord, kCoord), api.Sub(kCoord, jCoord)),
		api.Add(jCoord, kCoord))
	kTmpNegative = api.Select(kCoordNegative, api.Sub(1, jGreaterk), 0)

	// if j < 0
	iCoord = api.Select(jCoordNegative, api.Add(iCoord, jCoord), iCoord)
	jCoord = api.Select(jCoordNegative, 0, jCoord)
	kCoord = api.Select(jCoordNegative, kTmp, kCoord)
	kCoordNegative = api.Select(jCoordNegative, kTmpNegative, kCoordNegative)

	// if k < 0
	iCoord = api.Select(kCoordNegative, api.Add(iCoord, kCoord), iCoord)
	jCoord = api.Select(kCoordNegative, api.Add(jCoord, kCoord), jCoord)
	kCoord = api.Select(kCoordNegative, 0, kCoord)

	iGreaterj = api.IsZero(api.Sub(api.Cmp(iCoord, jCoord), 1)) // Check if i > j?
	min := api.Select(iGreaterj, jCoord, iCoord)
	min = api.Select(api.IsZero(api.Sub(api.Cmp(min, kCoord), 1)), kCoord, min)

	coordinates[0] = api.Sub(iCoord, min)
	coordinates[1] = api.Sub(jCoord, min)
	coordinates[2] = api.Sub(kCoord, min)

	return coordinates
}
