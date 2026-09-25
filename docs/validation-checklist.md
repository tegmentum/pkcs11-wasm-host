# SoftHSM Validation Checklist

This checklist tracks the minimum scenarios the host adapter must pass against SoftHSM before graduating from prototype status.

## Environment Prep
- [ ] Install SoftHSM v2 and initialize a test token with SO/user PINs (`softhsm2-util --init-token`).
- [ ] Configure the adapter with the SoftHSM module path via the slot-manager `initialize` config string.
- [ ] Export `SOFTHSM_LIB=/path/to/libsofthsm2.so` (or `PKCS11_MODULE_PATH`) so both the host integration test and the `guest-smoke` component can discover the provider automatically.
- [ ] Optionally add `slot=<id>` to the initialization config when you want to pin tests to a specific slot; mismatched slot usage will now return `slot-id-invalid` immediately.
- [ ] Optional: set `PKCS11_STATE_MECH` (decimal or `0x...`) before running the host adapter tests or the `guest-smoke` component to exercise `C_GetOperationState`/`C_SetOperationState` on a mechanism SoftHSM supports; both harnesses skip state serialization if the module returns `CKR_FUNCTION_NOT_SUPPORTED`.

## Slot and Session Lifecycle
- [ ] `get-slot-list(false)` returns both populated and empty slots, matching `softhsm2-util --show-slots`.
- [ ] `get-token-info` and `get-slot-info` populate the WIT records without truncation.
- [ ] `open-session` + `close` cycle runs cleanly multiple times with no leaked handles (verify via SoftHSM logs).
- [ ] `login` with `credential::inline` succeeds and zeroizes secrets; a second login yields `error-code::user-already-logged-in`.
- [ ] Tuple return from `generate-key-pair` successfully produces two managed `object` resources consumable by follow-up calls.

## Object Management
- [ ] `create-object` imports an AES secret key template and returns an `object` handle usable after session reconnect.
- [ ] `find-objects-init`/`search::next` iterate over stored objects; finish closes search properly.
- [ ] `object::destroy` removes transient objects and surfaces `error-code::attribute-read-only` when destroying persistent ones.

## Cryptography
- [ ] One-shot `encrypt`/`decrypt` with AES-GCM round-trips plaintext using SoftHSM-supported parameters.
- [ ] Multipart digest via `digest-init`/`update`/`final` matches OpenSSL SHA-256 output.
- [ ] `sign`/`verify` with ECDSA P-256 works for both one-shot and multipart flows.
- [ ] `wrap-key`/`unwrap-key` with RSA-OAEP reproduces an imported AES key.
- [ ] `generate-random` outputs non-zero bytes and `seed-random` accepts additional entropy.

## Error Paths
- [ ] Invalid mechanism combinations (e.g., AES key with RSA mechanism) return `error-code::mechanism-param-invalid` without crashing the token.
- [ ] Session teardown during active multipart operations triggers `abort` and leaves the token in a clean state.
- [ ] `wait-for-slot-event` wakes on token reinitialization and supports the `dont-block` flag returning immediately.

## Observability
- [ ] Adapter logs include slot/session identifiers but never raw PINs or key material.
- [ ] Metrics (if enabled) export counters for mechanism usage and error codes to aid debugging.

## Troubleshooting & Error Mapping
| Scenario | Expected `error-code` | Next action |
| --- | --- | --- |
| Token reports `CKR_BUFFER_TOO_SMALL` for `get-attributes` | `buffer-too-small` with returned `length-hint` | Reissue `object::get-attributes` using the hinted size; mark previous response as `partial = true`. |
| Login denied due to wrong PIN | `pin-incorrect` | Retry only when the provider indicates more attempts remain; bubble to caller when `token-info.user-pin-final-try` is set. |
| Mechanism mismatch (e.g., RSA key + GCM) | `mechanism-param-invalid` | Abort operation; require caller to supply a compatible template. |
| Driver removes token mid-operation | `device-removed` | Cancel the pending operation, call `slot-manager::close-all-sessions`, and wait for reinsertion before retrying. |
| Vendor module returns unknown code | `unknown(u32)` | Surface the numeric value and consult provider guide; avoid automatic retries until mapped. |
| Token reports `CKR_PIN_LOCKED` | `pin-locked` | Stop retry attempts, require SO reset via `slot-manager::init-token`, and log the final try count. |
| RNG refuses seeding (`CKR_RANDOM_SEED_NOT_SUPPORTED`) | `random-seed-not-supported` | Skip `seed-random` on this device and continue with `generate-random`; document limitation in provider guide. |
| `wait-for-slot-event` called with `dont-block` and no events | `no-event` | Return immediately; caller should back off or switch to blocking mode before retrying. |
