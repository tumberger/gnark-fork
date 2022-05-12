package stats

import (
	"encoding/gob"
	"fmt"
	"os"
	"sync"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"

	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
)

const nbCurves = 6

func CurveIdx(curve ecc.ID) int {
	switch curve {
	case ecc.BN254:
		return 0
	case ecc.BLS12_377:
		return 1
	case ecc.BLS12_381:
		return 2
	case ecc.BLS24_315:
		return 3
	case ecc.BW6_761:
		return 4
	case ecc.BW6_633:
		return 5
	default:
		panic("not implemented")
	}
}

func init() {
	if nbCurves != len(gnark.Curves()) {
		panic("expected nbCurves == len(gnark.Curves())")
	}
}

func NewGlobalStats() *globalStats {
	return &globalStats{
		Stats: make(map[string][backend.PLONK + 1][nbCurves + 1]snippetStats),
	}
}

func (s *globalStats) Save(path string) error {
	fStats, err := os.Create(path) //#nosec G304 -- ignoring internal pacakge s
	if err != nil {
		return err
	}

	encoder := gob.NewEncoder(fStats)
	err = encoder.Encode(s.Stats)
	_ = fStats.Close()
	return err
}

func (s *globalStats) Load(path string) error {
	fStats, err := os.Open(path) //#nosec G304 -- ignoring internal package
	if err != nil {
		return err
	}

	decoder := gob.NewDecoder(fStats)
	err = decoder.Decode(&s.Stats)
	_ = fStats.Close()
	return err
}

func NewSnippetStats(curve ecc.ID, backendID backend.ID, circuit frontend.Circuit) (snippetStats, error) {
	var newCompiler frontend.NewBuilder

	switch backendID {
	case backend.GROTH16:
		newCompiler = r1cs.NewBuilder
	case backend.PLONK:
		newCompiler = scs.NewBuilder
	default:
		panic("not implemented")
	}

	// TODO @gbotrel cleanu up
	var ccs frontend.CompiledConstraintSystem
	var err error
	switch curve {
	case ecc.BN254:
		ccs, err = frontend.Compile[fr_bn254.Element](newCompiler, circuit, frontend.IgnoreUnconstrainedInputs())
	case ecc.BLS12_377:
		ccs, err = frontend.Compile[fr_bls12377.Element](newCompiler, circuit, frontend.IgnoreUnconstrainedInputs())
	case ecc.BLS12_381:
		ccs, err = frontend.Compile[fr_bls12381.Element](newCompiler, circuit, frontend.IgnoreUnconstrainedInputs())
	case ecc.BLS24_315:
		ccs, err = frontend.Compile[fr_bls24315.Element](newCompiler, circuit, frontend.IgnoreUnconstrainedInputs())
	case ecc.BW6_633:
		ccs, err = frontend.Compile[fr_bw6633.Element](newCompiler, circuit, frontend.IgnoreUnconstrainedInputs())
	case ecc.BW6_761:
		ccs, err = frontend.Compile[fr_bw6761.Element](newCompiler, circuit, frontend.IgnoreUnconstrainedInputs())
	default:
		panic("not implemented")
	}

	if err != nil {
		return snippetStats{}, err
	}

	// ensure we didn't introduce regressions that make circuits less efficient
	nbConstraints := ccs.GetNbConstraints()
	internal, _, _ := ccs.GetNbVariables()

	return snippetStats{nbConstraints, internal}, nil
}

func (s *globalStats) Add(curve ecc.ID, backendID backend.ID, cs snippetStats, circuitName string) {
	s.Lock()
	defer s.Unlock()
	rs := s.Stats[circuitName]
	rs[backendID][CurveIdx(curve)] = cs
	s.Stats[circuitName] = rs
}

type Circuit struct {
	Circuit frontend.Circuit
	Curves  []ecc.ID
}

type globalStats struct {
	sync.RWMutex
	Stats map[string][backend.PLONK + 1][nbCurves + 1]snippetStats
}

type snippetStats struct {
	NbConstraints, NbInternalWires int
}

func (cs snippetStats) String() string {
	return fmt.Sprintf("nbConstraints: %d, nbInternalWires: %d", cs.NbConstraints, cs.NbInternalWires)
}
