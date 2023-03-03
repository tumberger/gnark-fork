package cs

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/iop"
	"github.com/consensys/gnark/backend/witness"
)

// PlonkTrace data of a solved plonk circuit to give to the wizard
type PlonkTrace struct {
	L, R, O            *iop.Polynomial
	Ql, Qr, Qm, Qo, Qk *iop.Polynomial
	S1, S2, S3         *iop.Polynomial
}

// buildPermutation builds the Permutation associated with a circuit.
//
// The permutation s is composed of cycles of maximum length such that
//
//	s. (l∥r∥o) = (l∥r∥o)
//
// , where l∥r∥o is the concatenation of the indices of l, r, o in
// ql.l+qr.r+qm.l.r+qo.O+k = 0.
//
// The permutation is encoded as a slice s of size 3*size(l), where the
// i-th entry of l∥r∥o is sent to the s[i]-th entry, so it acts on a tab
// like this: for i in tab: tab[i] = tab[permutation[i]]
func buildPermutation(spr *SparseR1CS, n uint64) []int64 {

	nbVariables := spr.NbInternalVariables + len(spr.Public) + len(spr.Secret)
	sizeSolution := int(n)

	// init permutation
	res := make([]int64, 3*sizeSolution)
	for i := 0; i < len(res); i++ {
		res[i] = -1
	}

	// init LRO position -> variable_ID
	lro := make([]int, 3*sizeSolution) // position -> variable_ID
	for i := 0; i < len(spr.Public); i++ {
		lro[i] = i // IDs of LRO associated to placeholders (only L needs to be taken care of)
	}

	offset := len(spr.Public)
	for i := 0; i < len(spr.Constraints); i++ { // IDs of LRO associated to constraints
		lro[offset+i] = spr.Constraints[i].L.WireID()
		lro[sizeSolution+offset+i] = spr.Constraints[i].R.WireID()
		lro[2*sizeSolution+offset+i] = spr.Constraints[i].O.WireID()
	}

	// init cycle:
	// map ID -> last position the ID was seen
	cycle := make([]int64, nbVariables)
	for i := 0; i < len(cycle); i++ {
		cycle[i] = -1
	}

	for i := 0; i < len(lro); i++ {
		if cycle[lro[i]] != -1 {
			// if != -1, it means we already encountered this value
			// so we need to set the corresponding permutation index.
			res[i] = cycle[lro[i]]
		}
		cycle[lro[i]] = int64(i)
	}

	// complete the Permutation by filling the first IDs encountered
	for i := 0; i < len(res); i++ {
		if res[i] == -1 {
			res[i] = cycle[lro[i]]
		}
	}
	return res
}

// SetupWoCommit generates the relevant public data for a plonk constraint system.
// The result can be passed to a different component (=the wizard iop) so the data
// can be processed (you can commit it, etc).
func SetupWoCommit(spr *SparseR1CS, publicWitness witness.Witness) PlonkTrace {

	var res PlonkTrace

	nbConstraints := len(spr.Constraints)

	// fft domains
	sizeSystem := uint64(nbConstraints + len(spr.Public)) // len(spr.Public) is for the placeholder constraints
	domain := *fft.NewDomain(sizeSystem)

	var cosetShift fr.Element
	cosetShift.Set(&domain.FrMultiplicativeGen)

	size := domain.Cardinality
	nbPublicVariables := len(spr.Public)

	// public polynomials corresponding to constraints: [ placholders | constraints | assertions ]
	ql := make([]fr.Element, domain.Cardinality)
	qr := make([]fr.Element, domain.Cardinality)
	qm := make([]fr.Element, domain.Cardinality)
	qo := make([]fr.Element, domain.Cardinality)
	qk := make([]fr.Element, domain.Cardinality)

	lagReg := iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}
	res.Ql = iop.NewPolynomial(&ql, lagReg)
	res.Qr = iop.NewPolynomial(&qr, lagReg)
	res.Qm = iop.NewPolynomial(&qm, lagReg)
	res.Qo = iop.NewPolynomial(&qo, lagReg)
	res.Qk = iop.NewPolynomial(&qk, lagReg)

	solution := publicWitness.Vector().(fr.Vector)

	for i := 0; i < nbPublicVariables; i++ { // placeholders (-PUB_INPUT_i + qk_i = 0) TODO should return error is size is inconsistant
		ql[i].SetOne().Neg(&ql[i])
		qr[i].SetZero()
		qm[i].SetZero()
		qo[i].SetZero()
		//qk[i].SetZero() // → to be completed by the prover
		qk[i].Set(&solution[i])
	}
	offset := len(spr.Public)
	for i := 0; i < nbConstraints; i++ { // constraints

		ql[offset+i].Set(&spr.Coefficients[spr.Constraints[i].L.CoeffID()])
		qr[offset+i].Set(&spr.Coefficients[spr.Constraints[i].R.CoeffID()])
		qm[offset+i].Set(&spr.Coefficients[spr.Constraints[i].M[0].CoeffID()]).
			Mul(&qm[offset+i], &spr.Coefficients[spr.Constraints[i].M[1].CoeffID()])
		qo[offset+i].Set(&spr.Coefficients[spr.Constraints[i].O.CoeffID()])
		qk[offset+i].Set(&spr.Coefficients[spr.Constraints[i].K])
	}

	// build permutation. Note: at this stage, the permutation takes in account the placeholders
	s := buildPermutation(spr, size)

	// set s1, s2, s3
	res.S1, res.S2, res.S3 = computePermutationPolynomials(s, &domain)

	return res

}

// computePermutationPolynomials computes the LDE (Lagrange basis) of the permutations
// s1, s2, s3.
//
// 1	z 	..	z**n-1	|	u	uz	..	u*z**n-1	|	u**2	u**2*z	..	u**2*z**n-1  |
//
//																						 |
//	      																				 | Permutation
//
// s11  s12 ..   s1n	   s21 s22 	 ..		s2n		     s31 	s32 	..		s3n		 v
// \---------------/       \--------------------/        \------------------------/
//
//	s1 (LDE)                s2 (LDE)                          s3 (LDE)
func computePermutationPolynomials(s []int64, d *fft.Domain) (*iop.Polynomial, *iop.Polynomial, *iop.Polynomial) {

	nbElmts := int(d.Cardinality)

	// Lagrange form of ID
	evaluationIDSmallDomain := getIDSmallDomain(d)

	// Lagrange form of S1, S2, S3
	s1 := make([]fr.Element, nbElmts)
	s2 := make([]fr.Element, nbElmts)
	s3 := make([]fr.Element, nbElmts)
	for i := 0; i < nbElmts; i++ {
		s1[i].Set(&evaluationIDSmallDomain[s[i]])
		s2[i].Set(&evaluationIDSmallDomain[s[nbElmts+i]])
		s3[i].Set(&evaluationIDSmallDomain[s[2*nbElmts+i]])
	}

	lagReg := iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}
	ps1 := iop.NewPolynomial(&s1, lagReg)
	ps2 := iop.NewPolynomial(&s1, lagReg)
	ps3 := iop.NewPolynomial(&s1, lagReg)

	return ps1, ps2, ps3
}

// getIDSmallDomain returns the Lagrange form of ID on the small domain
func getIDSmallDomain(domain *fft.Domain) []fr.Element {

	res := make([]fr.Element, 3*domain.Cardinality)

	res[0].SetOne()
	res[domain.Cardinality].Set(&domain.FrMultiplicativeGen)
	res[2*domain.Cardinality].Square(&domain.FrMultiplicativeGen)

	for i := uint64(1); i < domain.Cardinality; i++ {
		res[i].Mul(&res[i-1], &domain.Generator)
		res[domain.Cardinality+i].Mul(&res[domain.Cardinality+i-1], &domain.Generator)
		res[2*domain.Cardinality+i].Mul(&res[2*domain.Cardinality+i-1], &domain.Generator)
	}

	return res
}
