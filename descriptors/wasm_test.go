package descriptors

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCallback(t *testing.T) {
	result := getWasmMod().callbackTest(func(arg string) string {
		return "prefix - " + arg
	})
	require.Equal(t, "prefix - test - suffix", result)
}
