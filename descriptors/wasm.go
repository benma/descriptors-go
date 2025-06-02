package descriptors

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Network represents the different Bitcoin networks.
type Network int

const (
	// NetworkMainnet represents the main Bitcoin network.
	NetworkMainnet Network = 0

	// NetworkTestnet represents the Bitcoin testnet network.
	NetworkTestnet Network = 1

	// NetworkRegtest represents the Bitcoin regtest network.
	NetworkRegtest Network = 2
)

//go:embed wrapper.wasm
var wasmBytes []byte

var initOnce sync.Once

type wasmModule struct {
	mod api.Module
}

func (m *wasmModule) allocate(size uint32) (uint32, func()) {
	allocate := m.mod.ExportedFunction("allocate")
	results, err := allocate.Call(context.Background(), uint64(size))
	if err != nil {
		log.Panicln(err)
	}
	return uint32(results[0]), func() {
		m.deallocate(results[0], uint64(size))
	}
}

func (m *wasmModule) deallocate(ptr, size uint64) {
	deallocate := m.mod.ExportedFunction("deallocate")
	_, err := deallocate.Call(context.Background(), ptr, size)
	if err != nil {
		log.Panicln(err)
	}
}

func (m *wasmModule) descriptorParse(
	descriptor string) (uint32, func(), error) {

	strPtr, strDrop := rustString(descriptor)
	defer strDrop()
	parseFn := m.mod.ExportedFunction("descriptor_parse")
	result, err := parseFn.Call(context.Background(), strPtr)
	if err != nil {
		return 0, nil, err
	}
	var jsonResult struct {
		Ptr   uint32
		Error string
	}
	if err := jsonUnmarshal(result[0], &jsonResult); err != nil {
		return 0, nil, err
	}
	if jsonResult.Error != "" {
		return 0, nil, errors.New(jsonResult.Error)
	}
	descPtr := jsonResult.Ptr
	return descPtr, func() { m.descriptorDrop(uint64(descPtr)) }, nil
}

func (m *wasmModule) descriptorMultipathLen(descPtr uint64) uint64 {
	descriptorLenFn := m.mod.ExportedFunction("descriptor_multipath_len")
	results, err := descriptorLenFn.Call(context.Background(), descPtr)
	if err != nil {
		log.Panicln(err)
	}
	return results[0]
}

func (m *wasmModule) descriptorMaxWeightToSatisfy(descPtr uint64) (uint64, error) {
	fn := m.mod.ExportedFunction("descriptor_max_weight_to_satisfy")
	results, err := fn.Call(context.Background(), descPtr)
	if err != nil {
		log.Panicln(err)
	}
	var jsonResult struct {
		Weight uint64
		Error  *string
	}
	if err := jsonUnmarshal(results[0], &jsonResult); err != nil {
		return 0, err
	}
	if jsonResult.Error != nil {
		return 0, errors.New(*jsonResult.Error)
	}
	return jsonResult.Weight, nil

}

func (m *wasmModule) descriptorDrop(descPtr uint64) {
	descriptorDropFn := m.mod.ExportedFunction("descriptor_drop")
	_, err := descriptorDropFn.Call(context.Background(), descPtr)
	if err != nil {
		log.Panicln(err)
	}
}

func (m *wasmModule) descriptorAddressAt(
	descPtr uint64,
	network Network,
	multipathIndex uint32,
	derivationIndex uint32) (string, error) {
	fn := m.mod.ExportedFunction("descriptor_address_at")
	result, err := fn.Call(
		context.Background(),
		descPtr,
		uint64(network),
		uint64(multipathIndex),
		uint64(derivationIndex),
	)
	if err != nil {
		return "", err
	}
	var jsonResult struct {
		Address string
		Error   string
	}
	if err := jsonUnmarshal(result[0], &jsonResult); err != nil {
		return "", err
	}
	if jsonResult.Error != "" {
		return "", errors.New(jsonResult.Error)
	}
	return jsonResult.Address, nil
}

func (m *wasmModule) descriptorLift(descPtr uint64) (*SemanticPolicy, error) {
	fn := m.mod.ExportedFunction("descriptor_lift")
	results, err := fn.Call(context.Background(), descPtr)
	if err != nil {
		log.Panicln(err)
	}
	var jsonResult struct {
		Policy *SemanticPolicy `json:"policy"`
		Error  *string
	}
	if err := jsonUnmarshal(results[0], &jsonResult); err != nil {
		return nil, err
	}
	if jsonResult.Error != nil {
		return nil, errors.New(*jsonResult.Error)
	}
	return jsonResult.Policy, nil
}

func (m *wasmModule) descriptorKeys(descPtr uint64) []string {
	fn := m.mod.ExportedFunction("descriptor_keys")
	results, err := fn.Call(context.Background(), descPtr)
	if err != nil {
		log.Panicln(err)
	}
	var jsonResult []string
	if err := jsonUnmarshal(results[0], &jsonResult); err != nil {
		log.Panicln(err)
	}
	return jsonResult
}

func (m *wasmModule) descriptorDescType(descPtr uint64) string {
	fn := m.mod.ExportedFunction("descriptor_desc_type")
	results, err := fn.Call(context.Background(), descPtr)
	if err != nil {
		log.Panicln(err)
	}
	return fromRustString(results[0])
}

func (m *wasmModule) descriptorString(descPtr uint64) string {
	fn := m.mod.ExportedFunction("descriptor_to_str")
	result, err := fn.Call(context.Background(), descPtr)
	if err != nil {
		log.Panicln(err)
	}
	return fromRustString(result[0])
}

type miniscriptProperties struct {
	Types   string
	OpCodes uint64 `json:"op_codes"`
	Error   string
}

func (m *wasmModule) miniscriptParse(script string) (*miniscriptProperties,
	error) {

	strPtr, strDrop := rustString(script)
	defer strDrop()
	parseFn := m.mod.ExportedFunction("miniscript_parse")
	result, err := parseFn.Call(context.Background(), strPtr)
	if err != nil {
		return nil, err
	}
	var jsonResult miniscriptProperties
	if err := jsonUnmarshal(result[0], &jsonResult); err != nil {
		return nil, err
	}
	if jsonResult.Error != "" {
		return nil, errors.New(jsonResult.Error)
	}
	return &jsonResult, nil
}

func (m *wasmModule) miniscriptCompile(script string) ([]byte, error) {
	strPtr, strDrop := rustString(script)
	defer strDrop()
	parseFn := m.mod.ExportedFunction("miniscript_compile")
	result, err := parseFn.Call(context.Background(), strPtr)
	if err != nil {
		return nil, err
	}
	var jsonResult struct {
		ScriptHex string `json:"script_hex"`
		Error     string
	}
	if err := jsonUnmarshal(result[0], &jsonResult); err != nil {
		return nil, err
	}
	if jsonResult.Error != "" {
		return nil, errors.New(jsonResult.Error)
	}

	resultBytes, err := hex.DecodeString(jsonResult.ScriptHex)
	if err != nil {
		return nil, err
	}

	return resultBytes, nil
}

func (m *wasmModule) callbackTest(f func(string) string) string {
	fn := m.mod.ExportedFunction("callback_test")
	callbackId, cleanup := registerCallback(f)
	defer cleanup()
	results, err := fn.Call(context.Background(), uint64(callbackId))
	if err != nil {
		log.Panicln(err)
	}
	return fromRustString(results[0])
}

var wasmMod wasmModule

func logString(_ context.Context, m api.Module, offset, byteCount uint32) {
	buf, ok := m.Memory().Read(offset, byteCount)
	if !ok {
		log.Panicf("Memory.Read(%d, %d) out of range", offset,
			byteCount)
	}
	fmt.Println(string(buf))
}

func getWasmMod() *wasmModule {
	initOnce.Do(func() {
		ctx := context.Background()
		wasmRuntime := wazero.NewRuntime(ctx)
		wasi_snapshot_preview1.MustInstantiate(ctx, wasmRuntime)
		_, err := wasmRuntime.NewHostModuleBuilder("env").
			NewFunctionBuilder().
			WithFunc(logString).
			Export("log").
			NewFunctionBuilder().
			WithFunc(invokeCallback).
			Export("invoke_callback").
			Instantiate(ctx)
		if err != nil {
			log.Panicln(err)
		}

		mod, err := wasmRuntime.Instantiate(ctx, wasmBytes)
		if err != nil {
			log.Panicln(err)
		}
		wasmMod = wasmModule{mod}
	})
	return &wasmMod
}

func rustString(str string) (uint64, func()) {
	mod := getWasmMod()
	strSize := len(str)

	strPtr, freeStr := mod.allocate(uint32(strSize))

	if !mod.mod.Memory().Write(uint32(strPtr), []byte(str)) {
		log.Panicf("rustString Memory().Write")
	}
	return (uint64(strPtr) << 32) | uint64(strSize), freeStr
}

func fromRustString(ptr uint64) string {
	mod := getWasmMod()
	strPtr := uint32(ptr >> 32)
	strSize := uint32(ptr)
	defer mod.deallocate(uint64(strPtr), uint64(strSize))
	bytes, ok := mod.mod.Memory().Read(strPtr, strSize)
	if !ok {
		log.Panicf("Memory.Read(%d, %d) out of range of memory size %d",
			strPtr, strSize, mod.mod.Memory().Size())
	}
	return string(bytes)
}

func jsonUnmarshal(ptr uint64, result interface{}) error {
	return json.Unmarshal([]byte(fromRustString(ptr)), result)
}
