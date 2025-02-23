package descriptors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	testdataDir           = "testdata"
	derivationTestVectors = "derivation.json"
)

func parseNetwork(t *testing.T, network string) Network {
	switch network {
	case "mainnet":
		return NetworkMainnet
	case "testnet":
		return NetworkTestnet
	case "regtest":
		return NetworkRegtest
	default:
		require.FailNow(t, "unknown network: %s", network)
		return 0
	}
}

func TestDerivationVectors(t *testing.T) {
	vectors, err := readDerivationTestVectors()
	require.NoError(t, err)

	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			descriptor, err := NewDescriptor(vector.Descriptor)

			if vector.ExpectErr != "" {
				require.ErrorContains(t, err, vector.ExpectErr)
				return
			}

			require.NoError(t, err)
			defer descriptor.Close()

			require.EqualValues(
				t, vector.NumMultipath,
				descriptor.MultipathLen(),
			)

			expectedDescriptor := vector.Descriptor
			if !vector.HasChecksum {
				expectedDescriptor += vector.Checksum
			}
			require.Equal(
				t, expectedDescriptor, descriptor.String(),
			)

			for _, addr := range vector.Addresses {
				network := parseNetwork(t, addr.Network)

				parsedAddr, err := descriptor.AddressAt(
					network, addr.MultipathIndex,
					addr.DerivationIndex,
				)

				if addr.ExpectErr != "" {
					require.ErrorContains(
						t, err, addr.ExpectErr,
					)
					continue
				}

				require.NoError(t, err)
				require.Equal(t, addr.Address, parsedAddr)
			}
		})
	}
}

type testAddress struct {
	Network         string
	MultipathIndex  uint32
	DerivationIndex uint32
	Address         string
	ExpectErr       string
}

type derivationTestVector struct {
	Name         string
	Descriptor   string
	HasChecksum  bool
	Checksum     string
	NumMultipath uint32
	ExpectErr    string
	Addresses    []*testAddress
}

// readDerivationTestVectors reads the derivation test vectors from the test
// vector file.
func readDerivationTestVectors() ([]*derivationTestVector, error) {
	// Open the test vector file.
	file, err := os.Open(filepath.Join(testdataDir, derivationTestVectors))
	if err != nil {
		return nil, err
	}

	// Decode the test vectors.
	var testVectors []*derivationTestVector
	if err := json.NewDecoder(file).Decode(&testVectors); err != nil {
		return nil, err
	}

	return testVectors, nil
}
