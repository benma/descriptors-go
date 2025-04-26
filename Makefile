RUST_VERSION := 1.86.0

build-wrapper:
	cd wrapper && docker run --rm -v $$(pwd):/usr/src/app --entrypoint='' \
		rust:$(RUST_VERSION)-bullseye bash -c 'cd /usr/src/app; ./install-and-compile.sh'
	cp wrapper/target/wasm32-wasip1/release/wrapper.wasm descriptors/

check-wrapper-compiled: build-wrapper
	@$(call print, "Verifying wrapper is up to date.")
	if test -n "$$(git status --porcelain '*.wasm')"; then echo "WASM wrapper not compiled!"; git status --porcelain '*.wasm'; exit 1; fi

unit-test:
	go test -v ./...
