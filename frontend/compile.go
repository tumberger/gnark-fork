package frontend

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/logger"
)

// Compile will generate a ConstraintSystem from the given circuit
//
// 1. it will first allocate the user inputs (see type Tag for more info)
// example:
// 		type MyCircuit struct {
// 			Y frontend.Variable `gnark:"exponent,public"`
// 		}
// in that case, Compile() will allocate one public variable with id "exponent"
//
// 2. it then calls circuit.Define(curveID, R1CS) to build the internal constraint system
// from the declarative code
//
// 3. finally, it converts that to a ConstraintSystem.
// 		if zkpID == backend.GROTH16	→ R1CS
//		if zkpID == backend.PLONK 	→ SparseR1CS
//
// initialCapacity is an optional parameter that reserves memory in slices
// it should be set to the estimated number of constraints in the circuit, if known.

func ParseCircuit[E any, ptE field.Element[E]](builder Builder[E, ptE], circuit Circuit) (err error) {
	// ensure circuit.Define has pointer receiver
	if reflect.ValueOf(circuit).Kind() != reflect.Ptr {
		return errors.New("frontend.Circuit methods must be defined on pointer receiver")
	}

	// parse the schema, to count the number of public and secret variables
	s, err := schema.Parse(circuit, tVariable, nil)
	if err != nil {
		return err
	}
	log := logger.Logger()
	log.Info().Int("nbSecret", s.NbSecret).Int("nbPublic", s.NbPublic).Msg("parsed circuit inputs")

	// this not only set the schema, but sets the wire offsets for public, secret and internal wires
	builder.SetSchema(s)

	// leaf handlers are called when encoutering leafs in the circuit data struct
	// leafs are Constraints that need to be initialized in the context of compiling a circuit
	var handler schema.LeafHandler = func(visibility schema.Visibility, name string, tInput reflect.Value) error {
		if tInput.CanSet() {
			// log.Trace().Str("name", name).Str("visibility", visibility.String()).Msg("init input wire")
			switch visibility {
			case schema.Secret:
				tInput.Set(reflect.ValueOf(builder.AddSecretVariable(name)))
			case schema.Public:
				tInput.Set(reflect.ValueOf(builder.AddPublicVariable(name)))
			case schema.Unset:
				return errors.New("can't set val " + name + " visibility is unset")
			}

			return nil
		}
		return errors.New("can't set val " + name)
	}
	// recursively parse through reflection the circuits members to find all Constraints that need to be allocated
	// (secret or public inputs)
	_, err = schema.Parse(circuit, tVariable, handler)
	if err != nil {
		return err
	}

	// recover from panics to print user-friendlier messages
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v\n%s", r, debug.Stack())
		}
	}()

	// call Define() to fill in the Constraints
	if err = circuit.Define(builder); err != nil {
		return fmt.Errorf("define circuit: %w", err)
	}

	return
}

// CompileOption defines option for altering the behaviour of the Compile
// method. See the descriptions of the functions returning instances of this
// type for available options.
type CompileOption func(opt *CompileConfig) error

type CompileConfig struct {
	Capacity                  int
	IgnoreUnconstrainedInputs bool
}

// WithCapacity is a compile option that specifies the estimated capacity needed
// for internal variables and constraints. If not set, then the initial capacity
// is 0 and is dynamically allocated as needed.
func WithCapacity(capacity int) CompileOption {
	return func(opt *CompileConfig) error {
		opt.Capacity = capacity
		return nil
	}
}

// IgnoreUnconstrainedInputs is a compile option which allow compiling input
// circuits where not all inputs are not constrained. If not set, then the
// compiler returns an error if there exists an unconstrained input.
//
// This option is useful for debugging circuits, but should not be used in
// production settings as it means that there is a potential error in the
// circuit definition or that it is possible to optimize witness size.
func IgnoreUnconstrainedInputs() CompileOption {
	return func(opt *CompileConfig) error {
		opt.IgnoreUnconstrainedInputs = true
		return nil
	}
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A Variable }{}).FieldByName("A").Type()
}

// TODO @gbotrel find a home for this
type Field[E any, _ field.Element[E]] struct {
}

func (f *Field[E, ptE]) Bits() int {
	var one, qMinusOne E
	ptE(&one).SetOne()
	ptE(&qMinusOne).Sub(&qMinusOne, &one)
	ptE(&qMinusOne).FromMont()
	return ptE(&qMinusOne).BitLen()
}

func (f *Field[E, ptE]) Modulus() *big.Int {
	var one, qMinusOne E
	q := new(big.Int)
	ptE(&one).SetOne()
	ptE(&qMinusOne).Sub(&qMinusOne, &one)
	ptE(&qMinusOne).ToBigIntRegular(q)
	q.SetBit(q, 0, 1) // q - 1 is even
	return q
}
func (f *Field[E, ptE]) Curve() ecc.ID {
	// temporary hack for smoother refactoring
	q := f.Modulus()

	for _, c := range gnark.Curves() {
		if c.Info().Fr.Modulus().Cmp(q) == 0 {
			return c
		}
	}

	panic("not implemented")
}
