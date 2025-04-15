package descriptors

import (
	_ "embed"
)

// Descriptor is a struct encapsulating the parsed instance of a descriptor.
type Descriptor struct {
	mod   *wasmModule
	ptr   uint64
	close func()
}

// NewDescriptor parses the given descriptor string and returns a new
// Descriptor instance.
func NewDescriptor(descriptor string) (*Descriptor, error) {
	mod := getWasmMod()
	descPtr, close, err := mod.descriptorParse(descriptor)
	if err != nil {
		return nil, err
	}
	return &Descriptor{
		mod:   mod,
		ptr:   uint64(descPtr),
		close: close,
	}, nil
}

// Close releases the resources associated with the descriptor.
func (d *Descriptor) Close() {
	d.close()
}

// MultipathLen returns the number of multipath elements in the descriptor.
func (d *Descriptor) MultipathLen() int {
	return int(d.mod.descriptorMultipathLen(d.ptr))
}

// String returns the complete string representation of the descriptor,
// including the checksum.
func (d *Descriptor) String() string {
	return d.mod.descriptorString(d.ptr)
}

// AddressAt derives and returns the address at the given multipath and
// derivation index.
func (d *Descriptor) AddressAt(network Network, multipathIndex uint32,
	derivationIndex uint32) (string, error) {

	return d.mod.descriptorAddressAt(
		d.ptr, network, multipathIndex, derivationIndex,
	)
}
