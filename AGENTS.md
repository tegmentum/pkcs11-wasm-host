# Repository Guidelines

## Project Structure & Module Organization
- `host-adapter/`: Rust crate that exposes the `pkcs11:world/pkcs11` WIT world to native PKCS#11 providers. Source lives in `src/`; generated bindings will land in `src/bindings.rs` once `wit-bindgen` runs.
- `wit/`: Canonical WIT packages (`pkcs11-*`) plus `worlds/pkcs11.wit`, consumed via the `PKCS11_WIT_ROOT` env var during builds. Module-level APIs, slot/token metadata, and mechanism queries are defined in `pkcs11-core` and `pkcs11-token/slot-manager`.
- `docs/`: Design notes, validation checklists, and planning artifacts that explain architecture and roadmap assumptions.

## Build, Test, and Development Commands
- `cargo build --manifest-path host-adapter/Cargo.toml`: Compile the adapter and trigger `build.rs` so bindings can be generated.
- `PKCS11_WIT_ROOT=$(pwd)/wit cargo test --manifest-path host-adapter/Cargo.toml`: Execute unit and integration tests with the WIT root pointing at the local packages.
- `cargo fmt && cargo clippy --all-targets --all-features`: Enforce formatting and linting before opening a review.

## Coding Style & Naming Conventions
- Rust code follows `rustfmt` defaults (4-space indent, snake_case identifiers, UpperCamelCase types). Keep WIT items kebab-case to match existing packages.
- Prefer `anyhow::Result` for internal error paths and map to `pkcs11::core::ErrorCode` at the API surface.
- Log sensitive operations at `debug` level; avoid logging token or credential material.

## Testing Guidelines
- Add unit tests alongside implementations in `host-adapter/src/` using `#[cfg(test)]` modules.
- Integration tests should spin up SoftHSM or a vendor module via the configuration string (`module=/path/to/libsofthsm2.so`). Guard hardware-dependent tests behind feature flags.
- Aim for coverage of slot discovery, initialization/finalization flows, and error mapping from CK_RV codes to `ErrorCode` values.
- Extend coverage to new module-level calls (`get-info`, `get-slot-info`, `get-token-info`, mechanism enumeration) so regressions in metadata translation are caught early.
- Exercise session credential flows (SO/user login, PIN init/change), RNG usage, and object CRUD/search to verify the freshly wired PKCS#11 entry points.
- Add multipart encrypt/decrypt/sign/verify/digest cases that iterate over `chunk` updates and confirm finalization/abort paths cleanly reset session state.

## Commit & Pull Request Guidelines
- Use imperative, present-tense commit subjects (`Add slot finalizer`). Include body context when touching unsafe code or FFI boundaries.
- Reference tracking issues with `Refs #123` in the footer when applicable. Attach SoftHSM logs or screenshots for behavioral changes.
- Pull requests should describe impacted modules, testing performed, and any external module versions used. Request a second reviewer when modifying `bindings` or `ffi` surfaces.

## Security & Configuration Tips
- Never commit real HSM credentials or vendor libraries; rely on local paths and `.gitignore` for secrets.
- Validate that `PKCS11_WIT_ROOT` resolves to the checked-in `wit/` tree to avoid loading untrusted interface definitions.
- Review third-party PKCS#11 modules in a sandboxed environment and document any additional system dependencies in `docs/`.

## Provider Registry Usage
- Register new provider modules through the exported `provider-registry` interface so guests can enumerate providers without hard-coded paths.
- Use lowercase canonical names (e.g., `softhsm`) and absolute `module-path` values to avoid duplicate entries.
- Update `docs/provider-guides/` whenever a new provider is registered to keep setup scripts aligned with registry metadata.

## PKCS#11 Surface Coverage
- The WIT world now exposes module introspection (`get-info`), token reinitialization (`init-token`), mechanism list/info queries, and bulk session teardown to mirror the core PKCS#11 general-purpose functions.
- Mechanism, attribute, key-type, and object-class identifiers flow as numeric values (`CK_*`) to avoid gaps when new spec revisions ship.
- When adding new bindings, keep conversions centralized in `host-adapter/src/lib.rs` so FFI structs and flag mappers remain authoritative.
- Session resources now bridge login/logout, PIN lifecycle, RNG primitives, and object management/search onto the native driver; use these hooks rather than ad-hoc FFI wrappers.
- Multipart streaming helpers (`encryptor`, `decryptor`, `signer`, `verifier`, `digester`) directly call `C_*Init/C_*Update/C_*Final`, so prefer them over manual session state management when contributing new flows.
