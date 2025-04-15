build-wrapper:
	cd wrapper && cargo build --release --target wasm32-wasip1
	cp wrapper/target/wasm32-wasip1/release/wrapper.wasm descriptors/

check-wrapper-compiled: build-wrapper
	@$(call print, "Verifying wrapper is up to date.")
	if test -n "$$(git status --porcelain '*.wasm')"; then echo "WASM wrapper not compiled!"; git status --porcelain '*.wasm'; exit 1; fi

unit-test:
	go test -v ./...
