package dag

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDAGReduction(t *testing.T) {
	assert := require.New(t)

	// we start with
	// ┌────A
	// │    │
	// │    ▼
	// │    B
	// │    │
	// │    ▼
	// └───►C
	const (
		A = iota
		B
		C
		nbNodes
	)
	dag := New(nbNodes)
	// virtually adds A and B
	dag.AddNode()
	dag.AddNode()

	dag.AddEdges(B, []int{A})

	// virtuall adds C
	dag.AddNode()
	dag.AddEdges(C, []int{A, B})

	// we should get
	// 		A
	// 		│
	// 		▼
	// 		B
	// 		│
	// 		▼
	// 		C
	assert.Equal(0, len(dag.parents[A]))
	assert.Equal(1, len(dag.parents[B]))
	assert.Equal(1, len(dag.parents[C]))

	assert.Equal(A, dag.parents[B][0])
	assert.Equal(B, dag.parents[C][0])

	assert.Equal(1, len(dag.children[A]))
	assert.Equal(1, len(dag.children[B]))
	assert.Equal(0, len(dag.children[C]))

	assert.Equal(B, dag.children[A][0])
	assert.Equal(C, dag.children[B][0])

}

func TestDAGReductionFork(t *testing.T) {
	assert := require.New(t)

	// we start with this
	// ┌───────D◄────┐
	// │       ▲     │
	// │       │     │
	// │ A     B     C
	// │ │     │     │
	// │ │     ▼     │
	// │ └────►E ◄───┘
	// │       ▲
	// └───────┘
	const (
		A = iota
		B
		C
		D
		E
		nbNodes
	)

	dag := New(nbNodes)
	// virtually adds A,B,C,D
	dag.AddNode()
	dag.AddNode()
	dag.AddNode()
	dag.AddNode()

	dag.AddEdges(D, []int{B, C})

	// virtuall adds E
	dag.AddNode()
	dag.AddEdges(E, []int{A, B, C, D})

	// we should get
	// A     B     C
	// │     │     │
	// │     ▼     │
	// │     D ◄───┘
	// │     │
	// │     ▼
	// └────►E
	assert.Equal(0, len(dag.parents[A]))
	assert.Equal(0, len(dag.parents[B]))
	assert.Equal(0, len(dag.parents[C]))
	assert.Equal(2, len(dag.parents[D]))
	assert.Equal(2, len(dag.parents[E]))

	assert.Equal(C, dag.parents[D][0])
	assert.Equal(B, dag.parents[D][1])

	assert.Equal(D, dag.parents[E][0])
	assert.Equal(A, dag.parents[E][1])

	assert.Equal(1, len(dag.children[A]))
	assert.Equal(1, len(dag.children[B]))
	assert.Equal(1, len(dag.children[C]))
	assert.Equal(1, len(dag.children[D]))
	assert.Equal(0, len(dag.children[E]))

	assert.Equal(E, dag.children[A][0])
	assert.Equal(D, dag.children[B][0])
	assert.Equal(D, dag.children[C][0])
	assert.Equal(E, dag.children[D][0])

	// Check that levels are coherent
	levels := dag.Levels()

	// we should have 3 levels:
	// [A,B,C]
	// [D]
	// [E]
	assert.Equal(3, len(levels))
	assert.Equal(3, len(levels[0]))
	assert.Equal(1, len(levels[1]))
	assert.Equal(1, len(levels[2]))

	// level 0
	assert.Equal(A, levels[0][0])
	assert.Equal(B, levels[0][1])
	assert.Equal(C, levels[0][2])

	// level 1
	assert.Equal(D, levels[1][0])

	// level 2
	assert.Equal(E, levels[2][0])
}

func BenchmarkDAGReduction(b *testing.B) {
	rand.Seed(42)
	const nbNodes = 100000
	parents := make([]int, 0, nbNodes)
	for i := 0; i < b.N; i++ {
		dag := New(nbNodes)
		for j := 0; j < nbNodes/1000; j++ {
			dag.AddNode() // initial nodes
		}
		for j := nbNodes / 1000; j < nbNodes; j++ {
			parents = parents[:0]
			for k := 0; k < 10; k++ {
				parents = append(parents, rand.Intn(j-1))
			}
			dag.AddNode()
			dag.AddEdges(j, parents)
		}
	}
}
