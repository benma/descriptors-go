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

func TestInvalidUTF8DoesNotCorruptWasm(t *testing.T) {
	invalidUTF8 := string([]byte{0x81})

	tests := []struct {
		name  string
		call  func(string) error
		valid string
	}{
		{
			name: "descriptor",
			call: func(input string) error {
				_, err := NewDescriptor(input)
				return err
			},
			valid: "wsh(0)",
		},
		{
			name: "miniscript parse",
			call: func(input string) error {
				_, _, err := parseMiniscript(input)
				return err
			},
			valid: "0",
		},
		{
			name: "miniscript compile",
			call: func(input string) error {
				_, err := compileMiniscript(input)
				return err
			},
			valid: "0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.EqualError(t, test.call(invalidUTF8),
				"input is not valid UTF-8")
			require.NoError(t, test.call(test.valid))
		})
	}
}
