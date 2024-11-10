package descriptors

import (
	_ "embed"
)

type Descriptor struct {
	mod   *wasmModule
	ptr   uint64
	close func()
}

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

func (d *Descriptor) Close() {
	d.close()
}

func (d *Descriptor) MultipathLen() int {
	return int(d.mod.descriptorMultipathLen(d.ptr))
}

func (d *Descriptor) AddressAt(network Network, multipathIndex uint32, derivationIndex uint32) (string, error) {
	return d.mod.descriptorAddressAt(d.ptr, network, multipathIndex, derivationIndex)
}
