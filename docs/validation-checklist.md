# SoftHSM Validation Checklist

This checklist tracks the minimum scenarios the host adapter must pass against SoftHSM before graduating from prototype status.

## Environment Prep
- [ ] Install SoftHSM v2 and initialize a test token with SO/user PINs (`softhsm2-util --init-token`).
- [ ] Configure the adapter with the SoftHSM module path via the slot-manager `initialize` config string.

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
