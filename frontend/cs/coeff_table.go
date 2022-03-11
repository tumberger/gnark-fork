package cs

import (
	"math/big"

	"github.com/consensys/gnark/frontend/compiled"
)

type Element[T any] interface {
	SetInt64(int64) *T
	SetUint64(uint64) *T
	SetOne() *T
	SetString(string) *T
	SetInterface(i1 interface{}) (*T, error)
	Exp(T, *big.Int) *T
	Inverse(*T) *T
	Neg(*T) *T
	Double(*T) *T
	Mul(*T, *T) *T
	Add(*T, *T) *T
	Sub(*T, *T) *T
	Div(*T, *T) *T
	BitLen() int
	FromMont() *T
	Bit(i uint64) uint64
	Marshal() []byte
	IsUint64() bool
	Uint64() uint64

	ToBigIntRegular(res *big.Int) *big.Int

	IsZero() bool
	IsOne() bool

	Equal(*T) bool
	String() string

	*T
}

// CoeffTable helps build a constraint system but need not be serialized after compilation
type CoeffTable[E any, _ Element[E]] struct {
	// Coefficients in the constraints
	Coeffs         []E            // list of unique coefficients.
	CoeffsIDsLarge map[string]int // map to check existence of a coefficient (key = coeff.Bytes())
	CoeffsIDsInt64 map[int64]int  // map to check existence of a coefficient (key = int64 value)
}

func NewCoeffTable[E any, ptE Element[E]]() CoeffTable[E, ptE] {
	st := CoeffTable[E, ptE]{
		Coeffs:         make([]E, 4),
		CoeffsIDsLarge: make(map[string]int),
		CoeffsIDsInt64: make(map[int64]int, 4),
	}

	ptE(&st.Coeffs[compiled.CoeffIdZero]).SetInt64(0)
	ptE(&st.Coeffs[compiled.CoeffIdOne]).SetInt64(1)
	ptE(&st.Coeffs[compiled.CoeffIdTwo]).SetInt64(2)
	ptE(&st.Coeffs[compiled.CoeffIdMinusOne]).SetInt64(-1)
	st.CoeffsIDsInt64[0] = compiled.CoeffIdZero
	st.CoeffsIDsInt64[1] = compiled.CoeffIdOne
	st.CoeffsIDsInt64[2] = compiled.CoeffIdTwo
	st.CoeffsIDsInt64[-1] = compiled.CoeffIdMinusOne

	return st
}

// CoeffID tries to fetch the entry where b is if it exits, otherwise appends b to
// the list of Coeffs and returns the corresponding entry
func (t *CoeffTable[E, ptE]) CoeffID(v ptE) int {

	// if the coeff is a int64 we have a fast path.
	// if v.IsInt64() {
	// 	return t.coeffID64(v.Int64())
	// }

	// GobEncode is 3x faster than b.Text(16). Slightly slower than Bytes, but Bytes return the same
	// thing for -x and x .
	key := string(v.Marshal())

	// if the coeff is already stored, fetch its ID from the cs.CoeffsIDs map
	if idx, ok := t.CoeffsIDsLarge[key]; ok {
		return idx
	}

	// else add it in the cs.Coeffs map and update the cs.CoeffsIDs map
	resID := len(t.Coeffs)
	t.Coeffs = append(t.Coeffs, *v)
	t.CoeffsIDsLarge[key] = resID
	return resID
}

// func (t *CoeffTable[E, ptE]) coeffID64(v int64) int {
// 	if resID, ok := t.CoeffsIDsInt64[v]; ok {
// 		return resID
// 	} else {
// 		var bCopy big.Int
// 		bCopy.SetInt64(v)
// 		resID := len(t.Coeffs)
// 		t.Coeffs = append(t.Coeffs, bCopy)
// 		t.CoeffsIDsInt64[v] = resID
// 		return resID
// 	}
// }
