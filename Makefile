build-wrapper:
	cd wrapper && cargo build --release --target wasm32-wasip1
	cp wrapper/target/wasm32-wasip1/release/wrapper.wasm descriptors/
