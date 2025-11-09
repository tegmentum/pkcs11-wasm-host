# PKCS#11 Host Adapter Prototype

This crate will host the Rust implementation of the adapter that exposes the `pkcs11:world/pkcs11` component world to WebAssembly guest modules.

## Structure
- `src/lib.rs`: prototype implementation that will wrap native PKCS#11 handles, serialize WIT payloads, and manage resource lifetimes.
- `Cargo.toml`: declares dependencies required for dynamic loading (`libloading`), resource synchronization (`parking_lot`), zeroization, and Wasmtime component embedding.
- Generated bindings will live under `src/bindings.rs` once `wit-bindgen` is integrated into the build script.

## Usage notes
- `build.rs` publishes the `PKCS11_WIT_ROOT` environment variable so `wit-bindgen` can locate the WIT sources at compile time.
- Call `SlotManagerImpl::initialize` with a config string like `module=/usr/local/lib/softhsm/libsofthsm2.so` to load the PKCS#11 provider and invoke `C_Initialize`.
- `get-slot-list` already bridges to `C_GetSlotList`; additional interfaces will fill in token and mechanism metadata.

## Integration tests

The library ships with an optional smoke test that talks to a real PKCS#11 provider. Point the test harness at the module you want to exercise by exporting `PKCS11_MODULE_PATH` before running `cargo test`. For example, with SoftHSM2 on macOS:

```bash
export PKCS11_MODULE_PATH="/opt/homebrew/lib/softhsm/libsofthsm2.so"
# Optional: provide a user PIN so the test can log in and create a transient object
export PKCS11_USER_PIN="1234"
cargo test
```

If `PKCS11_MODULE_PATH` is absent (or the module reports no slots) the test is skipped automatically. When `PKCS11_USER_PIN` is not set the test still runs but omits the login/object lifecycle portion.

## Next steps
1. Extend the integration coverage to include login flows and object CRUD once a test token can be provisioned automatically.
2. Explore generating bindings during the build so downstream consumers do not need `wit-bindgen` locally.
