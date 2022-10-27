package sumcheck

import (
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/polynomial"
	"github.com/consensys/gnark/test"
	"math/bits"
	"os"
	"path/filepath"
	"testing"
)

type multilinSumcheckCircuit struct {
	ClaimedSum           frontend.Variable
	Polynomial           []frontend.Variable
	ProofPartialSumPolys [][]frontend.Variable
	HashPath             string `gnark:"-"`
}

func (c *multilinSumcheckCircuit) Define(api frontend.API) error {
	var transcript ArithmeticTranscript
	if hash, err := getHash(c.HashPath); err == nil {
		transcript = &MapHashTranscript{hashMap: hash}
	} else {
		return err
	}

	proof := interleaveSumcheckProof(c.ProofPartialSumPolys, nil)
	if err := Verify(api, singleMultilinLazyClaim{
		g:          c.Polynomial,
		claimedSum: c.ClaimedSum,
	}, proof, transcript); err != nil {
		return err
	}
	return nil
}

func getRunMultilin(dir string, testCaseInfo *TestCaseInfo) func(*testing.T) {

	return func(t *testing.T) {

		assignment := multilinSumcheckCircuit{
			ClaimedSum: toVariable(testCaseInfo.ClaimedSum),
			Polynomial: polynomial.MultiLin(sliceToVariableSlice(testCaseInfo.Values)),
			HashPath:   filepath.Join(dir, testCaseInfo.Hash),
		}

		assignment.ProofPartialSumPolys, _ = separateSumcheckProof(
			unmarshalSumcheckProof(testCaseInfo.Proof))

		circuit := multilinSumcheckCircuit{
			Polynomial:           hollow(assignment.Polynomial),
			ProofPartialSumPolys: hollow(assignment.ProofPartialSumPolys),
			HashPath:             assignment.HashPath,
		}

		test.NewAssert(t).ProverSucceeded(&circuit, &assignment)

	}

}

func getRun(dir string, testCaseInfo *TestCaseInfo) func(*testing.T) {
	switch testCaseInfo.Type {
	case "multilin":
		return getRunMultilin(dir, testCaseInfo)
	default:
		return func(t *testing.T) {
			t.Errorf("type \"%s\" unrecognized", testCaseInfo.Type)
		}
	}
}

func TestSumcheckVectors(t *testing.T) {

	var filename string
	var err error
	if filename, err = filepath.Abs("test_vectors/vectors.json"); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	dir := filepath.Dir(filename)

	var bytes []byte

	if bytes, err = os.ReadFile(filename); err != nil {
		t.Fatal(err)
	}

	var testCasesInfo TestCasesInfo
	if err = json.Unmarshal(bytes, &testCasesInfo); err != nil {
		t.Fatal(err)
	}

	for name, testCase := range testCasesInfo {
		t.Run(name, getRun(dir, testCase))
	}
}

type TestCasesInfo map[string]*TestCaseInfo

type TestCaseInfo struct {
	Type        string                 `json:"type"`
	Hash        string                 `json:"hash"`
	Values      []interface{}          `json:"values"`
	Description string                 `json:"description"`
	Proof       PrintableSumcheckProof `json:"proof"`
	ClaimedSum  interface{}            `json:"claimedSum"`
}

type singleMultilinLazyClaim struct {
	g          polynomial.MultiLin
	claimedSum frontend.Variable
}

func (c singleMultilinLazyClaim) VerifyFinalEval(api frontend.API, r []frontend.Variable, combinationCoeff frontend.Variable, purportedValue frontend.Variable, proof interface{}) error {
	val := c.g.Eval(api, r)
	api.AssertIsEqual(val, purportedValue)
	return nil
}

func (c singleMultilinLazyClaim) CombinedSum(api frontend.API, combinationCoeffs frontend.Variable) frontend.Variable {
	return c.claimedSum
}

func (c singleMultilinLazyClaim) Degree(i int) int {
	return 1
}

func (c singleMultilinLazyClaim) ClaimsNum() int {
	return 1
}

func (c singleMultilinLazyClaim) VarsNum() int {
	return bits.TrailingZeros(uint(len(c.g)))
}
