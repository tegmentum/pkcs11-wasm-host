# Host Adapter Prototype Plan

The initial host adapter will be implemented in Rust using the `wasmtime` component model APIs so we can embed the PKCS#11 WIT world into native applications and test against real tokens.

## Architecture
- Slot manager `initialize`/`finalize`/`get-slot-list` now call directly into the native module; configuration accepts strings of the form `module=/path/to/pkcs11.so`.
- **Loader**: resolves a PKCS#11 shared library path from configuration, loads it with `libloading`, and wires optional mutex callbacks when the provider signals legacy threading requirements.
- **Runtime bindings**: generated via `wit-bindgen` to obtain strongly typed shims for `pkcs11:world/pkcs11`. The adapter exports the slot manager interface and stores native handles inside Rust structs associated with WIT resources.
- **Handle registry**: maintains maps from `slot-id`, `session-handle`, and `object-handle` to their native counterparts, ensuring deterministic drop by implementing `Drop`/`ResourceTable` hooks that call `C_CloseSession`, `C_DestroyObject`, etc.
- **Error translation**: converts CKR_* constants into the `pkcs11:core/error-code` variant, with a fallback that records the raw numeric value for `vendor` or `unknown` cases.
- **Mechanism encoding helpers**: leverage the new `pkcs11:crypto/mechanism-parameter` records to serialize mechanism structs into native `CK_MECHANISM` memory before invoking the driver.
- **Module metadata**: `C_GetInfo`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetMechanismList`, and `C_GetMechanismInfo` are bridged through the slot manager so guests receive accurate module descriptors without vendor-specific shims.
- **Session orchestration**: `SessionImpl` now wraps login/logout, PIN lifecycle, RNG seeding/generation, and object CRUD/search flows via `C_Login`, `C_InitPIN`, `C_SetPIN`, `C_SeedRandom`, `C_GenerateRandom`, and `C_{Create,Copy,Destroy,Find}Object`.
- **Multipart crypto**: single-shot and streaming encrypt/decrypt/sign/verify/digest flows map onto `C_*Init/C_*Update/C_*Final` so Wasm guests can drive incremental operations using the WIT streaming resources.

## Credential & PIN Handling
- **Inline credentials**: when the guest passes `credential::inline`, the adapter copies the buffer into a stack-allocated vector, zeroizes it after the PKCS#11 call with `zeroize::Zeroizing`, and rejects buffers larger than the token’s maximum PIN length.
- **Provider-backed credentials**: prompts are delegated back into the guest via the `pin-provider` resource. The adapter tracks outstanding providers and ensures `pin-provider::clear` is called after each use.
- **Protected authentication path**: if the token advertises `token-flags::protected-authentication-path`, the adapter bypasses inline secrets and returns `error-code::pin-not-supported` unless the provider resource is used.
- **Audit logging**: sensitive values are never logged; errors include only high-level status codes and slot identifiers.

## Concurrency
- Sessions are wrapped in `Arc<Mutex<_>>` so the adapter can enforce the PKCS#11 rule that only one active stateful operation is in flight per session. The adapter will lock around multi-part state until `final`/`abort` is called.
- Slot manager operations are executed on a central executor to serialize `C_Initialize`/`C_Finalize` while allowing sessions to run concurrently.

## Testing Strategy
- Start with SoftHSM v2: provisioning scripts create test tokens, import keys, and exercise enumeration, login, signing, and key generation flows.
- Add optional integration jobs gated behind environment variables for hardware tokens (YubiHSM, network HSM) to monitor vendor-specific mechanism behaviour.
- Provide fixture Wasm components (e.g., “list certificates”, “sign message”) to validate the adapter end-to-end.

## Open Tasks
- Define binary serialization between `mechanism-parameter` and `mechanism.parameter` fields in `pkcs11:core/mechanism`.
- Decide how to surface asynchronous provider interactions (e.g., waiting on `C_WaitForSlotEvent`) in the adapter runtime.
- Explore caching policies for objects keyed by handle vs. re-querying attributes on each call.
- Round out advanced flows such as `C_SignRecover{Init}`, `C_VerifyRecover{Init}`, `C_DigestKey`, and `C_GetObjectSize` to finish the PKCS#11 surface.
## Provider Integration Next Steps
- Track automation priorities and setup scripts in `docs/provider-integration-roadmap.md`.
- Deliver provisioning helpers for SoftHSM, OpenSC, and YubiHSM 2 before onboarding additional hardware.
- Land cloud HSM stubs behind feature flags so CI can simulate remote slots without credentials.
- Expose new providers through the `provider-registry` export so guests can discover registered modules without hard-coded paths.
