# Repository Guidelines

## Project Structure & Module Organization
The `host-adapter/` crate exposes the `pkcs11:world/pkcs11` WIT world; all Rust sources live in `host-adapter/src/` with generated bindings emitted to `src/bindings.rs` during `build.rs`. Canonical WIT packages reside in `wit/` and should be referenced through `PKCS11_WIT_ROOT=$(pwd)/wit` to avoid external drift. Design plans, validation matrices, and provider notes are captured under `docs/`, so align new features with the documented assumptions before coding.

## Build, Test, and Development Commands
`cargo build --manifest-path host-adapter/Cargo.toml` compiles the adapter and refreshes bindings. Run `PKCS11_WIT_ROOT=$(pwd)/wit cargo test --manifest-path host-adapter/Cargo.toml` for unit and integration coverage; keep the env var in place so tests load the in-tree WIT packages. Lint and formatting checks use `cargo fmt && cargo clippy --all-targets --all-features`, and must pass prior to opening a review.

## Coding Style & Naming Conventions
Rust code follows default `rustfmt` (4-space indentation, snake_case identifiers, UpperCamelCase types). Model new error paths with `anyhow::Result` internally and translate to `pkcs11::core::ErrorCode` at the boundary. Keep WIT symbols kebab-case and route all PKCS#11 conversions through `host-adapter/src/lib.rs` so FFI structures stay centralized. Log sensitive operations at `debug` level only.

## Testing Guidelines
Unit tests live next to their modules in `host-adapter/src/` using `#[cfg(test)]`; integration suites should launch SoftHSM or a vendor module via `module=/path/to/libsofthsm2.so`. Cover slot discovery, initialization/finalization, RNG, session credential flows, and object CRUD/search. Add multipart encrypt/decrypt/sign/verify/digest scenarios that exercise the `C_*Init/C_*Update/C_*Final` paths and confirm session cleanup. Feature-gate hardware-dependent suites and document any external modules in `docs/`.

## Commit & Pull Request Guidelines
Use imperative, present-tense commit subjects (e.g., “Add slot finalizer”) and include context for unsafe or FFI-heavy changes. Reference tracking issues with `Refs #123` when applicable and attach logs or screenshots for behavioral updates. Pull requests should summarize affected modules, list testing performed, note PKCS#11 providers or module versions, and seek a second reviewer when touching bindings or FFI layers.

## Security & Configuration Tips
Never commit real HSM credentials or vendor binaries; point configurations at local paths and rely on `.gitignore`. Validate that `PKCS11_WIT_ROOT` resolves to the checked-in `wit/` tree before builds to prevent loading untrusted interfaces. Register providers through the `provider-registry` interface using lowercase canonical names and absolute module paths, and update `docs/provider-guides/` whenever registry metadata changes.
