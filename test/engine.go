/*
Copyright © 2021 ConsenSys Software Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package test

import (
	"fmt"
	"math/big"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend/schema"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"

	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	fr_bls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
)

// engine implements frontend.API
//
// it is used for a faster verification of witness in tests
// and more importantly, for fuzzing purposes
//
// it converts the inputs to the API to big.Int (after a mod reduce using the curve base field)
type engine[E any, ptE element[E]] struct {
	eOpts   engineOpts
	curveID ecc.ID
	q       *big.Int
}

type engineOpts struct {
	opt backend.ProverConfig
	// mHintsFunctions map[hint.ID]hintFunction
	constVars  bool
	apiWrapper ApiWrapper
}

// TestEngineOption defines an option for the test engine.
type TestEngineOption func(e *engineOpts) error

// ApiWrapper defines a function which wraps the API given to the circuit.
type ApiWrapper func(frontend.API) frontend.API

// WithApiWrapper is a test engine option which which wraps the API before
// calling the Define method in circuit. If not set, then API is not wrapped.
func WithApiWrapper(wrapper ApiWrapper) TestEngineOption {
	return func(e *engineOpts) error {
		e.apiWrapper = wrapper
		return nil
	}
}

// SetAlLVariablesAsConstants is a test engine option which makes the calls to
// IsConstant() and ConstantValue() always return true. If this test engine
// option is not set, then all variables are considered as non-constant,
// regardless if it is constructed by a call to ConstantValue().
func SetAllVariablesAsConstants() TestEngineOption {
	return func(e *engineOpts) error {
		e.constVars = true
		return nil
	}
}

// WithBackendProverOptions is a test engine option which allows to define
// prover options. If not set, then default prover configuration is used.
func WithBackendProverOptions(opts ...backend.ProverOption) TestEngineOption {
	return func(e *engineOpts) error {
		cfg, err := backend.NewProverConfig(opts...)
		if err != nil {
			return fmt.Errorf("new prover config: %w", err)
		}
		e.opt = cfg
		return nil
	}
}

// IsSolved returns an error if the test execution engine failed to execute the given circuit
// with provided witness as input.
//
// The test execution engine implements frontend.API using big.Int operations.
//
// This is an experimental feature.
func IsSolved(circuit, witness frontend.Circuit, field *big.Int, opts ...TestEngineOption) (err error) {
	e, err := newEngine(field, opts...)
	if err != nil {
		return err
	}

	// TODO handle opt.LoggerOut ?

	// we clone the circuit, in case the circuit has some attributes it uses in its Define function
	// set by the user.
	// then, we set all the variables values to the ones from the witness

	// clone the circuit
	c := shallowClone(circuit)

	// set the witness values
	copyWitness(c, witness)

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v\n%s", r, string(debug.Stack()))
		}
	}()

	api := e.callApiWrapper()
	err = c.Define(api)

	return
}

func (e *engine[E, ptE]) callApiWrapper() frontend.API {
	return e.eOpts.apiWrapper(e)
}

func (e *engine[E, ptE]) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	var res E
	ptE(&res).Add(e.toElement(i1), e.toElement(i2))
	for i := 0; i < len(in); i++ {
		ptE(&res).Add(&res, e.toElement(in[i]))
	}
	// ptE(&res).Mod(res, e.modulus())
	return res
}

func (e *engine[E, ptE]) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	var res E
	ptE(&res).Sub(e.toElement(i1), e.toElement(i2))
	for i := 0; i < len(in); i++ {
		ptE(&res).Sub(&res, e.toElement(in[i]))
	}
	// ptE(&res).Mod(res, e.modulus())
	return res
}

func (e *engine[E, ptE]) Neg(i1 frontend.Variable) frontend.Variable {
	var res E
	ptE(&res).Neg(e.toElement(i1))
	// ptE(&res).Mod(res, e.modulus())
	return res
}

func (e *engine[E, ptE]) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	var res E
	ptE(&res).Mul(e.toElement(i1), e.toElement(i2))
	// ptE(&res).Mod(res, e.modulus())
	for i := 0; i < len(in); i++ {
		ptE(&res).Mul(&res, e.toElement(in[i]))
		// ptE(&res).Mod(res, e.modulus())
	}
	return res
}

func (e *engine[E, ptE]) Div(i1, i2 frontend.Variable) frontend.Variable {
	var res E
	b2 := e.toElement(i2)
	if ptE(b2).IsZero() {
		panic("no inverse")
	}
	ptE(&res).Inverse(b2)
	ptE(&res).Mul(&res, e.toElement(i1))
	return res
}

func (e *engine[E, ptE]) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	var res E
	b1, b2 := e.toElement(i1), e.toElement(i2)
	if ptE(b1).IsUint64() && ptE(b2).IsUint64() && ptE(b1).Uint64() == 0 && ptE(b2).Uint64() == 0 {
		return 0
	}
	if ptE(b2).IsZero() {
		panic("no inverse")
	}
	ptE(&res).Inverse(b2)
	ptE(&res).Mul(&res, b1)
	// ptE(&res).Mod(res, e.modulus())
	return res
}

func (e *engine[E, ptE]) Inverse(i1 frontend.Variable) frontend.Variable {
	var res E
	b1 := e.toElement(i1)
	if ptE(b1).IsZero() {
		panic("no inverse")
	}
	ptE(&res).Inverse(b1)
	return res
}

func (e *engine[E, ptE]) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	nbBits := e.FieldBitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("invalid n")
		}
	}

	b1 := e.toElement(i1)
	ptE(b1).FromMont()

	if ptE(b1).BitLen() > nbBits {
		panic(fmt.Sprintf("[ToBinary] decomposing %s (bitLen == %d) with %d bits", ptE(b1).String(), ptE(b1).BitLen(), nbBits))
	}

	r := make([]frontend.Variable, nbBits)
	ri := make([]frontend.Variable, nbBits)
	for i := uint64(0); i < uint64(len(r)); i++ {
		r[i] = (ptE(b1).Bit(i))
		ri[i] = r[i]
	}

	// this is a sanity check, it should never happen
	value := e.toElement(e.FromBinary(ri...))
	ptE(value).FromMont()
	if !ptE(value).Equal(b1) {
		panic(fmt.Sprintf("[ToBinary] decomposing %s (bitLen == %d) with %d bits reconstructs into %s", ptE(b1).String(), ptE(b1).BitLen(), nbBits, ptE(value).String()))
	}
	return r
}

func (e *engine[E, ptE]) FromBinary(v ...frontend.Variable) frontend.Variable {
	bits := make([]*big.Int, len(v))
	for i := 0; i < len(v); i++ {
		bits[i] = e.toBigInt(v[i])
		if !(bits[i].IsUint64() && bits[i].Uint64() <= 1) {
			panic("bit is not boolean ") // TODO @gbotrel fixme
		}
		// e.mustBeBoolean(bits[i])
	}

	// Σ (2**i * bits[i]) == r
	// var r E
	// var tmp, c E
	// ptE(&c).SetUint64(1)
	c := new(big.Int)
	r := new(big.Int)
	tmp := new(big.Int)
	c.SetUint64(1)

	for i := 0; i < len(bits); i++ {
		tmp.Mul(bits[i], c)
		r.Add(r, tmp)
		c.Lsh(c, 1)
		// ptE(&tmp).Mul(bits[i], &c)
		// ptE(&r).Add(&r, &tmp)
		// ptE(&c).Double(&c) // lsh 1
	}
	// r.Mod(r, e.modulus())

	return r
}

func (e *engine[E, ptE]) Xor(i1, i2 frontend.Variable) frontend.Variable {
	b1, b2 := e.toElement(i1), e.toElement(i2)
	e.mustBeBoolean(b1)
	e.mustBeBoolean(b2)
	var res E
	ptE(&res).SetUint64(ptE(b1).Uint64() ^ ptE(b2).Uint64())
	return res
}

func (e *engine[E, ptE]) Or(i1, i2 frontend.Variable) frontend.Variable {
	b1, b2 := e.toElement(i1), e.toElement(i2)
	e.mustBeBoolean(b1)
	e.mustBeBoolean(b2)
	var res E
	ptE(&res).SetUint64(ptE(b1).Uint64() | ptE(b2).Uint64())
	return res
}

func (e *engine[E, ptE]) And(i1, i2 frontend.Variable) frontend.Variable {
	b1, b2 := e.toElement(i1), e.toElement(i2)
	e.mustBeBoolean(b1)
	e.mustBeBoolean(b2)
	var res E
	ptE(&res).SetUint64(ptE(b1).Uint64() & ptE(b2).Uint64())
	return res
}

// Select if b is true, yields i1 else yields i2
func (e *engine[E, ptE]) Select(b frontend.Variable, i1, i2 frontend.Variable) frontend.Variable {
	b1 := e.toElement(b)
	e.mustBeBoolean(b1)

	if ptE(b1).Uint64() == 1 {
		return e.toElement(i1)
	}
	return (e.toElement(i2))
}

// Lookup2 performs a 2-bit lookup between i1, i2, i3, i4 based on bits b0
// and b1. Returns i0 if b0=b1=0, i1 if b0=1 and b1=0, i2 if b0=0 and b1=1
// and i3 if b0=b1=1.
func (e *engine[E, ptE]) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {
	s0 := e.toElement(b0)
	s1 := e.toElement(b1)
	e.mustBeBoolean(s0)
	e.mustBeBoolean(s1)
	var lookup E
	ptE(&lookup).Double(s1)
	ptE(&lookup).Add(&lookup, s0)
	return e.toElement([]frontend.Variable{i0, i1, i2, i3}[ptE(&lookup).Uint64()])
}

// IsZero returns 1 if a is zero, 0 otherwise
func (e *engine[E, ptE]) IsZero(i1 frontend.Variable) frontend.Variable {
	b1 := e.toElement(i1)

	if ptE(b1).IsUint64() && ptE(b1).Uint64() == 0 {
		return big.NewInt(1)
	}

	return big.NewInt(0)
}

// Cmp returns 1 if i1>i2, 0 if i1==i2, -1 if i1<i2
func (e *engine[E, ptE]) Cmp(i1, i2 frontend.Variable) frontend.Variable {
	b1 := e.toElement(i1)
	b2 := e.toElement(i2)
	var res E
	ptE(&res).SetInt64(int64(ptE(b1).Cmp(b2)))
	// ptE(&res).Mod(res, e.modulus())
	return res
}

func (e *engine[E, ptE]) AssertIsEqual(i1, i2 frontend.Variable) {
	b1, b2 := e.toElement(i1), e.toElement(i2)
	if !ptE(b1).Equal(b2) {
		panic(fmt.Sprintf("[assertIsEqual] %s == %s", ptE(b1).String(), ptE(b2).String()))
	}
}

func (e *engine[E, ptE]) AssertIsDifferent(i1, i2 frontend.Variable) {
	b1, b2 := e.toElement(i1), e.toElement(i2)
	if ptE(b1).Equal(b2) {
		panic(fmt.Sprintf("[assertIsDifferent] %s != %s", ptE(b1).String(), ptE(b2).String()))
	}
}

func (e *engine[E, ptE]) AssertIsBoolean(i1 frontend.Variable) {
	b1 := e.toElement(i1)
	e.mustBeBoolean(b1)
}

func (e *engine[E, ptE]) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	// TODO @gbotrel may not need big int here, just in case bound is larger than modulus?
	bValue := e.toBigInt(bound)

	if bValue.Sign() == -1 {
		panic(fmt.Sprintf("[assertIsLessOrEqual] bound (%s) must be positive", bValue.String()))
	}

	b1 := e.toBigInt(v)
	if b1.Cmp(bValue) == 1 {
		panic(fmt.Sprintf("[assertIsLessOrEqual] %s > %s", b1.String(), bValue.String()))
	}
}

func (e *engine[E, ptE]) Println(a ...frontend.Variable) {
	var sbb strings.Builder
	sbb.WriteString("(test.engine) ")

	// prefix log line with file.go:line
	if _, file, line, ok := runtime.Caller(1); ok {
		sbb.WriteString(filepath.Base(file))
		sbb.WriteByte(':')
		sbb.WriteString(strconv.Itoa(line))
		sbb.WriteByte(' ')
	}

	for i := 0; i < len(a); i++ {
		v := e.toElement(a[i])
		sbb.WriteString(ptE(v).String())
		sbb.WriteByte(' ')
	}
	fmt.Println(sbb.String())
}

func (e *engine[E, ptE]) NewHint(f hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {

	if nbOutputs <= 0 {
		return nil, fmt.Errorf("hint function must return at least one output")
	}

	in := make([]*big.Int, len(inputs))

	for i := 0; i < len(inputs); i++ {
		in[i] = e.toBigInt(inputs[i])
	}
	res := make([]*big.Int, nbOutputs)
	for i := range res {
		res[i] = new(big.Int)
	}

	err := f(e.Field(), in, res)

	if err != nil {
		panic("NewHint: " + err.Error())
	}

	out := make([]frontend.Variable, len(res))
	for i := range res {
		var el E
		// res[i].Mod(res[i], e.q)
		ptE(&el).SetInterface(res[i])
		out[i] = el
	}

	return out, nil
}

// IsConstant returns true if v is a constant known at compile time
func (e *engine[E, ptE]) IsConstant(v frontend.Variable) bool {
	return e.eOpts.constVars
}

// ConstantValue returns the big.Int value of v
func (e *engine[E, ptE]) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	r := e.toBigInt(v)
	// TODO @gbotrel could avoid mod op here by using elements
	return r, e.eOpts.constVars
}

func (e *engine[E, ptE]) IsBoolean(v frontend.Variable) bool {
	r := e.toElement(v)
	return ptE(r).IsUint64() && ptE(r).Uint64() <= 1
}

func (e *engine[E, ptE]) MarkBoolean(v frontend.Variable) {
	if !e.IsBoolean(v) {
		panic("mark boolean a non-boolean value")
	}
}

func (e *engine[E, ptE]) Tag(name string) frontend.Tag {
	// do nothing, we don't measure constraints with the test engine
	return frontend.Tag{Name: name}
}

func (e *engine[E, ptE]) AddCounter(from, to frontend.Tag) {
	// do nothing, we don't measure constraints with the test engine
}

func (e *engine[E, ptE]) toBigInt(i1 frontend.Variable) *big.Int {
	switch vv := i1.(type) {
	case *big.Int:
		return vv
	case big.Int:
		return &vv
	default:
		b := utils.FromInterface(i1)
		b.Mod(&b, e.q)
		return &b
	}
}

func (e *engine[E, ptE]) toElement(i1 frontend.Variable) *E {
	switch vv := i1.(type) {
	case *E:
		return vv
	case E:
		return &vv
	default:
		b := utils.FromInterface(i1)
		var r E
		ptE(&r).SetInterface(b)
		return &r
	}
}

// bitLen returns the number of bits needed to represent a fr.Element
func (e *engine[E, ptE]) FieldBitLen() int {
	return e.q.BitLen()
}

func (e *engine[E, ptE]) mustBeBoolean(b *E) {
	if !ptE(b).IsUint64() || !(ptE(b).Uint64() == 0 || ptE(b).Uint64() == 1) {
		panic(fmt.Sprintf("[assertIsBoolean] %s", ptE(b).String()))
	}
}

// shallowClone clones given circuit
// this is actually a shallow copy → if the circuits contains maps or slices
// only the reference is copied.
func shallowClone(circuit frontend.Circuit) frontend.Circuit {

	cValue := reflect.ValueOf(circuit).Elem()
	newCircuit := reflect.New(cValue.Type())
	newCircuit.Elem().Set(cValue)

	circuitCopy, ok := newCircuit.Interface().(frontend.Circuit)
	if !ok {
		panic("couldn't clone the circuit")
	}

	if !reflect.DeepEqual(circuitCopy, circuit) {
		panic("clone failed")
	}

	return circuitCopy
}

func copyWitness(to, from frontend.Circuit) {
	var wValues []interface{}

	collectHandler := func(f *schema.Field, tInput reflect.Value) error {
		v := tInput.Interface().(frontend.Variable)

		if f.Visibility == schema.Secret || f.Visibility == schema.Public {
			if v == nil {
				return fmt.Errorf("when parsing variable %s: missing assignment", f.FullName)
			}
			wValues = append(wValues, v)
		}
		return nil
	}
	if _, err := schema.Parse(from, tVariable, collectHandler); err != nil {
		panic(err)
	}

	i := 0
	setHandler := func(f *schema.Field, tInput reflect.Value) error {
		if f.Visibility == schema.Secret || f.Visibility == schema.Public {
			tInput.Set(reflect.ValueOf((wValues[i])))
			i++
		}
		return nil
	}
	// this can't error.
	_, _ = schema.Parse(to, tVariable, setHandler)

}

func (e *engine[E, ptE]) Field() *big.Int {
	return e.q
}

func (e *engine[E, ptE]) Compiler() frontend.Compiler {
	return e
}

func newEngine(field *big.Int, opts ...TestEngineOption) (api, error) {
	// yet another "type switch", yes, it's ugly, but it keeps generic away from user-facing api for now.
	if field.Cmp(ecc.BN254.ScalarField()) == 0 {
		e := &engine[fr_bn254.Element, *fr_bn254.Element]{
			curveID: utils.FieldToCurve(field),
			q:       new(big.Int).Set(field),
			eOpts: engineOpts{
				apiWrapper: func(a frontend.API) frontend.API { return a },
				constVars:  false,
			},
		}

		for _, opt := range opts {
			if err := opt(&e.eOpts); err != nil {
				return nil, fmt.Errorf("apply option: %w", err)
			}
		}
		return e, nil
	}

	if field.Cmp(ecc.BLS12_381.ScalarField()) == 0 {
		e := &engine[fr_bls12381.Element, *fr_bls12381.Element]{
			curveID: utils.FieldToCurve(field),
			q:       new(big.Int).Set(field),
			eOpts: engineOpts{
				apiWrapper: func(a frontend.API) frontend.API { return a },
				constVars:  false,
			},
		}

		for _, opt := range opts {
			if err := opt(&e.eOpts); err != nil {
				return nil, fmt.Errorf("apply option: %w", err)
			}
		}
		return e, nil
	}

	if field.Cmp(ecc.BLS12_377.ScalarField()) == 0 {
		e := &engine[fr_bls12377.Element, *fr_bls12377.Element]{
			curveID: utils.FieldToCurve(field),
			q:       new(big.Int).Set(field),
			eOpts: engineOpts{
				apiWrapper: func(a frontend.API) frontend.API { return a },
				constVars:  false,
			},
		}

		for _, opt := range opts {
			if err := opt(&e.eOpts); err != nil {
				return nil, fmt.Errorf("apply option: %w", err)
			}
		}
		return e, nil
	}

	if field.Cmp(ecc.BLS24_315.ScalarField()) == 0 {
		e := &engine[fr_bls24315.Element, *fr_bls24315.Element]{
			curveID: utils.FieldToCurve(field),
			q:       new(big.Int).Set(field),
			eOpts: engineOpts{
				apiWrapper: func(a frontend.API) frontend.API { return a },
				constVars:  false,
			},
		}

		for _, opt := range opts {
			if err := opt(&e.eOpts); err != nil {
				return nil, fmt.Errorf("apply option: %w", err)
			}
		}
		return e, nil
	}

	if field.Cmp(ecc.BLS24_317.ScalarField()) == 0 {
		e := &engine[fr_bls24317.Element, *fr_bls24317.Element]{
			curveID: utils.FieldToCurve(field),
			q:       new(big.Int).Set(field),
			eOpts: engineOpts{
				apiWrapper: func(a frontend.API) frontend.API { return a },
				constVars:  false,
			},
		}

		for _, opt := range opts {
			if err := opt(&e.eOpts); err != nil {
				return nil, fmt.Errorf("apply option: %w", err)
			}
		}
		return e, nil
	}

	if field.Cmp(ecc.BW6_633.ScalarField()) == 0 {
		e := &engine[fr_bw6633.Element, *fr_bw6633.Element]{
			curveID: utils.FieldToCurve(field),
			q:       new(big.Int).Set(field),
			eOpts: engineOpts{
				apiWrapper: func(a frontend.API) frontend.API { return a },
				constVars:  false,
			},
		}

		for _, opt := range opts {
			if err := opt(&e.eOpts); err != nil {
				return nil, fmt.Errorf("apply option: %w", err)
			}
		}
		return e, nil
	}

	if field.Cmp(ecc.BW6_761.ScalarField()) == 0 {
		e := &engine[fr_bw6761.Element, *fr_bw6761.Element]{
			curveID: utils.FieldToCurve(field),
			q:       new(big.Int).Set(field),
			eOpts: engineOpts{
				apiWrapper: func(a frontend.API) frontend.API { return a },
				constVars:  false,
			},
		}

		for _, opt := range opts {
			if err := opt(&e.eOpts); err != nil {
				return nil, fmt.Errorf("apply option: %w", err)
			}
		}
		return e, nil
	}

	// TODO @gbotrel could wrap big.Int in a struct that implements element constraints
	panic("unsupported modulus in test engine")
}
