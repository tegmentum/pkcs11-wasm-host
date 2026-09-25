# Immediate Development Next Steps

Mechanism and attribute schema guidance now lives in `docs/mechanism-encoding.md` and `docs/resource-lifecycle.md`. Keep those references up-to-date when adding new WIT records or CKM constants, and focus the immediate effort on the remaining host adapter and documentation workstreams below.

## Host Adapter Prototype Spike
- Wire a minimal `wasmtime` component inside `host-adapter/src/lib.rs` that loads one PKCS#11 shared library via `libloading`, maps `C_GetInfo`/slot enumeration, and returns structured errors so we can verify resource tables and drop semantics.
- Capture library-loading abstractions (path discovery, mutex callbacks) in `docs/host-adapter-plan.md` and convert them into Rust traits in `host-adapter/src/loader.rs` to unblock parallel work on sandboxing.
- Implement secure credential handling: add Zeroizing buffers for `credential::inline` requests and ensure `pin-provider::clear` is invoked in all login paths. Document the zeroization policy in `docs/resource-lifecycle.md`.
- Stand up the first integration test using SoftHSM by extending `guest-smoke/` with a component that lists slots, logs in, and fetches RNG bytes. Guard it behind an env var (`SOFTHSM_LIB`) so CI can opt in. The harness also honors an optional `PKCS11_STATE_MECH` flag so state serialization (`C_GetOperationState`/`C_SetOperationState`) can be validated when a driver supports it.

## Documentation & Provider Alignment
- Expand the provider guides under `docs/provider-guides/` whenever new fixtures land (SoftHSM setup script changes, OpenSC container tweaks, YubiHSM connector recipes) and cross-link them from the roadmap.
- Keep the troubleshooting matrix in `docs/validation-checklist.md` fresh by adding new scenarios whenever integration tests uncover driver-specific quirks.
- Update `docs/wit-package-map.md` after each schema change to prevent drift between WIT packages and Rust bindings, and include references to the host modules that consume each package so component changes are easy to audit.
