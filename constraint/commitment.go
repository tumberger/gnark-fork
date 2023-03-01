package constraint

import (
	"math/big"
)

const CommitmentDst = "bsb22-commitment"

type Commitment struct {
	Committed        []int // sorted list of id's of committed variables
	PrivateCommitted []int
	PublicCommitted  []int
}

func NewCommitment(committed []int, nbPublic int, injected []int) Commitment {
	res := Commitment{
		Committed:        committed,
		PrivateCommitted: make([]int, 0),
		PublicCommitted:  make([]int, 0),
	}

	iI := 0
	for _, cI := range committed {
		if cI < nbPublic {
			res.PublicCommitted = append(res.PublicCommitted, cI)
		} else if iI < len(injected) && injected[iI] == cI {
			res.PublicCommitted = append(res.PublicCommitted, cI)
			iI++
		} else {
			res.PrivateCommitted = append(res.PrivateCommitted, cI)
		}
	}

	return res
}

func (i *Commitment) NbCommitted() int {
	return len(i.Committed)
}

func (i *Commitment) Is() bool {
	return len(i.Committed) != 0
}

func (i *Commitment) SerializeCommitment(privateCommitment []byte, publicCommitted []*big.Int, fieldByteLen int) []byte {

	res := make([]byte, len(privateCommitment)+len(publicCommitted)*fieldByteLen)
	copy(res, privateCommitment)

	offset := len(privateCommitment)
	for j, inJ := range publicCommitted {
		offset += j * fieldByteLen
		inJ.FillBytes(res[offset : offset+fieldByteLen])
	}

	return res
}
