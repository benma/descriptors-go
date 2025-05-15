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

// String returns the complete string representation of the descriptor,
// including the checksum.
func (d *Descriptor) String() string {
	return d.mod.descriptorString(d.ptr)
}

// MultipathLen returns the number of multipath elements in the descriptor.
func (d *Descriptor) MultipathLen() int {
	return int(d.mod.descriptorMultipathLen(d.ptr))
}

// MaxWeightToSatisfy returns the largest possible weight of the input witness needed to satisfy this
// descriptor.
// See https://docs.rs/miniscript/12.3.2/miniscript/descriptor/enum.Descriptor.html#method.max_weight_to_satisfy.
func (d *Descriptor) MaxWeightToSatisfy() (uint64, error) {
	return d.mod.descriptorMaxWeightToSatisfy(d.ptr)
}

// AddressAt derives and returns the address at the given multipath and
// derivation index.
func (d *Descriptor) AddressAt(network Network, multipathIndex uint32,
	derivationIndex uint32) (string, error) {

	return d.mod.descriptorAddressAt(
		d.ptr, network, multipathIndex, derivationIndex,
	)
}

// Lift converts this descriptor into an abstract policy.
//
// See https://docs.rs/miniscript/12.3.2/miniscript/descriptor/enum.Descriptor.html#method.lift.
func (d *Descriptor) Lift() (*SemanticPolicy, error) {
	return d.mod.descriptorLift(d.ptr)
}

// Keys returns all keys present in the descriptor, in order as they appear in the descriptor
// string.
func (d *Descriptor) Keys() []string {
	return d.mod.descriptorKeys(d.ptr)
}
