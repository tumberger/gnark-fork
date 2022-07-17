package test

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

type api interface {
	frontend.API
	callApiWrapper() frontend.API
}

type element[T any] interface {
	SetInt64(int64) *T
	SetUint64(uint64) *T
	SetOne() *T
	SetString(string) *T
	SetInterface(i1 interface{}) (*T, error)
	SetBigInt(v *big.Int) *T
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
	ToMont() *T
	Bit(i uint64) uint64
	Marshal() []byte
	IsUint64() bool
	Uint64() uint64
	Cmp(*T) int

	ToBigIntRegular(res *big.Int) *big.Int

	IsZero() bool
	IsOne() bool

	Equal(*T) bool
	String() string

	*T
}
