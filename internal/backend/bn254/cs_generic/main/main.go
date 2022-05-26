package main

import (
	"fmt"
	"math/bits"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
)

const N = 10000000

func main() {
	// var f field[Element]
	// f.newElement = func() Element {
	// 	return Element{}
	// }
	start := time.Now()

	for i := 0; i < N; i++ {
		_ = noGeneric()
		_ = generic[fr.Element]()
		// _ = generic2[Element](f)
	}

	fmt.Println(time.Since(start).Milliseconds())
}

func noGeneric() Element {
	var a, b, c Element
	a.Add(&b, &c)
	return a
}

func generic[E any, ptE ElementG[E]]() E {
	var a, b, c E
	ptE(&a).Add(&b, &c)
	return a
}

type ElementG[T any] interface {
	Add(*T, *T) *T
	*T
}

func generic2[E elementV[E]](f field[E]) E {
	// a := f.newElement()
	b := f.newElement()
	c := f.newElement()
	// var b, c E
	// b := new(E)
	// c := new(E)
	return b.Add2(c)
}

type field[E elementV[E]] struct {
	newElement func() E
}

type elementV[T any] interface {
	Add2(T) T
	*T
}

type Element [4]uint64

// Add z = x + y mod q
func (z *Element) Add(x, y *Element) *Element {
	_addGeneric(z, x, y)
	return z
}

func (z Element) Add2(y Element) Element {
	var carry uint64
	z[0], carry = bits.Add64(z[0], y[0], 0)
	z[1], carry = bits.Add64(z[1], y[1], carry)
	z[2], carry = bits.Add64(z[2], y[2], carry)
	z[3], _ = bits.Add64(z[3], y[3], carry)

	// if z >= q → z -= q
	// note: this is NOT constant time
	if !(z[3] < 3486998266802970665 || (z[3] == 3486998266802970665 && (z[2] < 13281191951274694749 || (z[2] == 13281191951274694749 && (z[1] < 2896914383306846353 || (z[1] == 2896914383306846353 && (z[0] < 4891460686036598785))))))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 4891460686036598785, 0)
		z[1], b = bits.Sub64(z[1], 2896914383306846353, b)
		z[2], b = bits.Sub64(z[2], 13281191951274694749, b)
		z[3], _ = bits.Sub64(z[3], 3486998266802970665, b)
	}
	return z
}

func _addGeneric(z, x, y *Element) {

	var carry uint64
	z[0], carry = bits.Add64(x[0], y[0], 0)
	z[1], carry = bits.Add64(x[1], y[1], carry)
	z[2], carry = bits.Add64(x[2], y[2], carry)
	z[3], _ = bits.Add64(x[3], y[3], carry)

	// if z >= q → z -= q
	// note: this is NOT constant time
	if !(z[3] < 3486998266802970665 || (z[3] == 3486998266802970665 && (z[2] < 13281191951274694749 || (z[2] == 13281191951274694749 && (z[1] < 2896914383306846353 || (z[1] == 2896914383306846353 && (z[0] < 4891460686036598785))))))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 4891460686036598785, 0)
		z[1], b = bits.Sub64(z[1], 2896914383306846353, b)
		z[2], b = bits.Sub64(z[2], 13281191951274694749, b)
		z[3], _ = bits.Sub64(z[3], 3486998266802970665, b)
	}
}
