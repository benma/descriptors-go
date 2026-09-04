package descriptors

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"weak"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero/api"
)

type blockingFunction struct {
	api.Function
	entered chan<- struct{}
	release <-chan struct{}
}

func (f *blockingFunction) Call(context.Context, ...uint64) ([]uint64, error) {
	close(f.entered)
	<-f.release
	return []uint64{1}, nil
}

type singleFunctionModule struct {
	api.Module
	function api.Function
}

func (m *singleFunctionModule) ExportedFunction(string) api.Function {
	return m.function
}

func blockingModule() (*wasmModule, <-chan struct{}, chan<- struct{}) {
	entered := make(chan struct{})
	release := make(chan struct{})
	function := &blockingFunction{entered: entered, release: release}
	return &wasmModule{
		mod:    &singleFunctionModule{function: function},
		callMu: new(sync.Mutex),
	}, entered, release
}

//go:noinline
func descriptorMultipathLen(descriptor *Descriptor, result chan<- int) {
	result <- descriptor.MultipathLen()
}

//go:noinline
func planSatisfactionWeight(plan *Plan, result chan<- uint64) {
	result <- plan.SatisfactionWeight()
}

//go:noinline
func startDescriptorMultipathLen(module *wasmModule, result chan<- int) weak.Pointer[Descriptor] {
	descriptor := &Descriptor{mod: module, ptr: 1}
	descriptorRef := weak.Make(descriptor)
	go descriptorMultipathLen(descriptor, result)
	return descriptorRef
}

//go:noinline
func startPlanSatisfactionWeight(module *wasmModule, result chan<- uint64) weak.Pointer[Plan] {
	plan := &Plan{mod: module, ptr: 1}
	planRef := weak.Make(plan)
	go planSatisfactionWeight(plan, result)
	return planRef
}

func TestDescriptorRemainsAliveDuringCall(t *testing.T) {
	module, entered, release := blockingModule()
	result := make(chan int, 1)
	descriptorRef := startDescriptorMultipathLen(module, result)
	<-entered

	runtime.GC()
	alive := descriptorRef.Value() != nil
	close(release)
	require.Equal(t, 1, <-result)
	require.True(t, alive, "descriptor became unreachable during a method call")
}

func TestPlanRemainsAliveDuringCall(t *testing.T) {
	module, entered, release := blockingModule()
	result := make(chan uint64, 1)
	planRef := startPlanSatisfactionWeight(module, result)
	<-entered

	runtime.GC()
	alive := planRef.Value() != nil
	close(release)
	require.Equal(t, uint64(1), <-result)
	require.True(t, alive, "plan became unreachable during a method call")
}
