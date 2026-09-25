# PKCS#11 Host Adapter Prototype

This crate will host the Rust implementation of the adapter that exposes the `pkcs11:world/pkcs11` component world to WebAssembly guest modules.

## Structure
- `src/lib.rs`: prototype implementation that will wrap native PKCS#11 handles, serialize WIT payloads, and manage resource lifetimes.
- `Cargo.toml`: declares dependencies required for dynamic loading (`libloading`), resource synchronization (`parking_lot`), zeroization, and Wasmtime component embedding.
- Generated bindings will live under `src/bindings.rs` once `wit-bindgen` is integrated into the build script.

## Usage notes
- `build.rs` publishes the `PKCS11_WIT_ROOT` environment variable so `wit-bindgen` can locate the WIT sources at compile time.
- Call `SlotManagerImpl::initialize` with a config string like `module=/usr/local/lib/softhsm/libsofthsm2.so,mutex=os` to load the PKCS#11 provider and invoke `C_Initialize`. The optional `mutex` key toggles whether the adapter advertises OS-level locking (`os`, default) or requests legacy app-managed locking (`none`), and `slot=<id>` can be supplied to force a specific slot (all subsequent calls will return `slot-id-invalid` if they reference a different slot). Dual-purpose crypto updates (`digest-encrypt`, `decrypt-digest`, `sign-encrypt`, `decrypt-verify`) are exposed on the session interface when the backend driver supports them.
- When `initialize(None)` is called, the adapter falls back to the most recent config or the `SOFTHSM_LIB`/`PKCS11_MODULE_PATH` environment variables, so CI jobs can inject module paths without modifying code. You can inspect the currently loaded module via `AdapterContext::config_summary()` to double-check what path/mutex/slot settings were picked up.
- `get-slot-list` already bridges to `C_GetSlotList`; additional interfaces fill in token/mechanism metadata and can now listen for insert/remove events via `slot-manager::wait-for-slot-event` (mapped to `C_WaitForSlotEvent`, honoring the `dont-block` flag).
- Set `PKCS11_MODULE_ROOTS=/opt/pkcs11:/usr/local/lib/pkcs11` (colon-separated) to restrict the filesystem loader to those directories. Paths outside the allowlist will be rejected before attempting to load the shared object.

## Integration tests

The library ships with an optional smoke test that talks to a real PKCS#11 provider. Point the test harness at the module you want to exercise by exporting `SOFTHSM_LIB` (or the legacy `PKCS11_MODULE_PATH`) before running `cargo test`. For example, with SoftHSM2 on macOS:

```bash
export SOFTHSM_LIB="/opt/homebrew/lib/softhsm/libsofthsm2.so"
# Optional: provide a user PIN so the test can log in and create a transient object
export PKCS11_USER_PIN="1234"
# Optional: set a mechanism (decimal or 0x-prefixed) to exercise operation-state save/restore
export PKCS11_STATE_MECH="0x00000250"
cargo test
```

If neither environment variable is present (or the module reports no slots) the test is skipped automatically. When `PKCS11_USER_PIN` is not set the test still runs but omits the login/object lifecycle portion.

## Next steps
1. Use `scripts/softhsm-setup.sh` to configure a disposable SoftHSM token for the smoke tests (the script respects `SOFTHSM_TOKEN_DIR`, `SOFTHSM_SO_PIN`, `SOFTHSM_USER_PIN`, `SOFTHSM_LABEL`, and `SOFTHSM_IMPORT_DEMO=0` to skip importing the demo RSA/AES keys).
2. Explore generating bindings during the build so downstream consumers do not need `wit-bindgen` locally.
