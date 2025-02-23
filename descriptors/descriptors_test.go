package descriptors

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDescriptorSingle(t *testing.T) {
	descriptorStr := "wpkh(xpub6BzikmgQmvoYG3ShFhXU1LFKaUeU832dHoYL6ka9JpCqKXr7PTHQHaoSMbGU36CZNcoryVPsFBjt9aYyCQHtYi6BQTo6VfRv9xVRuSNNteB/*)"
	checksum := "#97qc8vss"
	descriptor, err := NewDescriptor(descriptorStr)
	require.NoError(t, err)
	defer descriptor.Close()
	require.Equal(t, 1, descriptor.MultipathLen())
	require.Equal(t, descriptorStr+checksum, descriptor.String())

	addr, err := descriptor.AddressAt(NetworkMainnet, 0, 0)
	require.NoError(t, err)
	require.Equal(t, "bc1qaz3jjsgpe29v5yzrvd58hsjgx5a9msujsgmyte", addr)

	_, err = descriptor.AddressAt(NetworkMainnet, 1, 0)
	require.Error(t, err)
}

func TestDescriptorMultipath(t *testing.T) {
	descriptorStr := "wpkh(xpub6BzikmgQmvoYG3ShFhXU1LFKaUeU832dHoYL6ka9JpCqKXr7PTHQHaoSMbGU36CZNcoryVPsFBjt9aYyCQHtYi6BQTo6VfRv9xVRuSNNteB/<0;1>/*)"
	checksum := "#w3nj0e22"
	descriptor, err := NewDescriptor(descriptorStr)
	require.NoError(t, err)
	defer descriptor.Close()

	require.Equal(t, 2, descriptor.MultipathLen())
	require.Equal(t, descriptorStr+checksum, descriptor.String())

	// First receive address.
	addr, err := descriptor.AddressAt(NetworkMainnet, 0, 0)
	require.NoError(t, err)
	require.Equal(t, "bc1qrdu5f9wfw3ppxmejnqe6rexd7fqkujnpzar5es", addr)

	// 11th receive address.
	addr, err = descriptor.AddressAt(NetworkMainnet, 0, 10)
	require.NoError(t, err)
	require.Equal(t, "bc1qsmp7eq2jt00llmsqmtatwavkjkdmrrz9klgd5g", addr)

	// First change address.
	addr, err = descriptor.AddressAt(NetworkMainnet, 1, 0)
	require.NoError(t, err)
	require.Equal(t, "bc1qlh4ln6vjdkz89um8gtzfmpf6wnt56lwy4u466g", addr)

	// 11th change address.
	addr, err = descriptor.AddressAt(NetworkMainnet, 1, 10)
	require.NoError(t, err)
	require.Equal(t, "bc1qpnmw93dscgt9m6shjq0v83z02tcljf8yfc9j7l", addr)
}

func TestNetworksWpkh(t *testing.T) {
	descriptorStr := "wpkh(xpub6BzikmgQmvoYG3ShFhXU1LFKaUeU832dHoYL6ka9JpCqKXr7PTHQHaoSMbGU36CZNcoryVPsFBjt9aYyCQHtYi6BQTo6VfRv9xVRuSNNteB/<0;1>/*)"
	checksum := "#w3nj0e22"
	descriptor, err := NewDescriptor(descriptorStr)
	require.NoError(t, err)
	defer descriptor.Close()

	require.Equal(t, descriptorStr+checksum, descriptor.String())

	addr, err := descriptor.AddressAt(NetworkMainnet, 0, 0)
	require.NoError(t, err)
	require.Equal(t, "bc1qrdu5f9wfw3ppxmejnqe6rexd7fqkujnpzar5es", addr)

	addr, err = descriptor.AddressAt(NetworkTestnet, 0, 0)
	require.NoError(t, err)
	require.Equal(t, "tb1qrdu5f9wfw3ppxmejnqe6rexd7fqkujnpgmc8zr", addr)

	addr, err = descriptor.AddressAt(NetworkRegtest, 0, 0)
	require.NoError(t, err)
	require.Equal(t, "bcrt1qrdu5f9wfw3ppxmejnqe6rexd7fqkujnp2jp242", addr)
}

func TestNetworksTr(t *testing.T) {
	descriptorStr := "tr(xpub6BzikmgQmvoYG3ShFhXU1LFKaUeU832dHoYL6ka9JpCqKXr7PTHQHaoSMbGU36CZNcoryVPsFBjt9aYyCQHtYi6BQTo6VfRv9xVRuSNNteB/<0;1>/*)"
	checksum := "#rq20sev9"
	descriptor, err := NewDescriptor(descriptorStr)
	require.NoError(t, err)
	defer descriptor.Close()

	require.Equal(t, descriptorStr+checksum, descriptor.String())

	addr, err := descriptor.AddressAt(NetworkMainnet, 0, 0)
	require.NoError(t, err)
	require.Equal(t, "bc1puc00mgvj7hh25y8uhpux7gudjp9a986awgtemtxdfx6kcv4dkl5qt275jk", addr)

	addr, err = descriptor.AddressAt(NetworkTestnet, 0, 0)
	require.NoError(t, err)
	require.Equal(t, "tb1puc00mgvj7hh25y8uhpux7gudjp9a986awgtemtxdfx6kcv4dkl5quzgmge", addr)

	addr, err = descriptor.AddressAt(NetworkRegtest, 0, 0)
	require.NoError(t, err)
	require.Equal(t, "bcrt1puc00mgvj7hh25y8uhpux7gudjp9a986awgtemtxdfx6kcv4dkl5q3mzaar", addr)
}

func TestInvalidChecksum(t *testing.T) {
	_, err := NewDescriptor("tr([e81a5744/48'/0'/0'/2']xpub6Duv8Gj9gZeA3sUo5nUMPEv6FZ81GHn3feyaUej5KqcjPKsYLww4xBX4MmYZUPX5NqzaVJWYdYZwGLECtgQruG4FkZMh566RkfUT2pbzsEg/<0;1>/*,and_v(v:pk([3c157b79/48'/0'/0'/2']xpub6DdSN9RNZi3eDjhZWA8PJ5mSuWgfmPdBduXWzSP91Y3GxKWNwkjyc5mF9FcpTFymUh9C4Bar45b6rWv6Y5kSbi9yJDjuJUDzQSWUh3ijzXP/<0;1>/*),older(65535)))#lg9nqqha")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid checksum")
}

func TestTapminiscript(t *testing.T) {
	descriptorStr := "tr([e81a5744/48'/0'/0'/2']xpub6Duv8Gj9gZeA3sUo5nUMPEv6FZ81GHn3feyaUej5KqcjPKsYLww4xBX4MmYZUPX5NqzaVJWYdYZwGLECtgQruG4FkZMh566RkfUT2pbzsEg/<0;1>/*,and_v(v:pk([3c157b79/48'/0'/0'/2']xpub6DdSN9RNZi3eDjhZWA8PJ5mSuWgfmPdBduXWzSP91Y3GxKWNwkjyc5mF9FcpTFymUh9C4Bar45b6rWv6Y5kSbi9yJDjuJUDzQSWUh3ijzXP/<0;1>/*),older(65535)))#lg9nqqhr"
	descriptor, err := NewDescriptor(descriptorStr)
	require.NoError(t, err)
	defer descriptor.Close()

	require.Equal(t, 2, descriptor.MultipathLen())
	require.Equal(t, descriptorStr, descriptor.String())

	// First receive address.
	addr, err := descriptor.AddressAt(NetworkMainnet, 0, 0)
	require.NoError(t, err)
	require.Equal(t, "bc1pfujezshxnw0jw2m9fn6hz0xr3ljjpjd30gtpqyymgxqquk8rr95qk986dz", addr)

	// First change address.
	addr, err = descriptor.AddressAt(NetworkMainnet, 1, 0)
	require.NoError(t, err)
	require.Equal(t, "bc1ptd9ngyt09kxtt8mkf832vhxdrn0xhccwp9jv6mz6vv4wqfc8dxjql2y0fn", addr)
}
