package runner

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunWithThreadsReturnsEveryInput(t *testing.T) {
	inputs := []string{
		"192.0.2.1",
		"192.0.2.2",
		"192.0.2.3",
		"192.0.2.4",
		"198.51.100.1",
		"198.51.100.2",
		"203.0.113.1",
		"203.0.113.2",
	}

	var mu sync.Mutex
	got := map[string]int{}
	runner := NewRunner(&Options{
		Inputs:  inputs,
		Threads: 4,
		Exclude: true,
		OnResult: func(result Output) {
			mu.Lock()
			got[result.Input]++
			mu.Unlock()
		},
	})

	require.NoError(t, runner.Run())
	require.Len(t, got, len(inputs))
	for _, input := range inputs {
		require.Equal(t, 1, got[input])
	}
}
