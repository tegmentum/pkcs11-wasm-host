# Open Questions & TODOs

## Mechanism Coverage
- Extend `pkcs11:core/mechanism-type` to include less common algorithms (e.g., EdDSA, ChaCha20-Poly1305, vendor-specific IDs) and confirm numeric interoperability strategy.
- Model remaining mechanism parameter structs (e.g., RSA key wrapping, X9.42 DH, TLS key material) that still require bespoke records.
- Decide how to represent mechanism-specific options that require nested structures (e.g., CK_RSA_PKCS_PSS_PARAMS) without forcing consumers to pack raw bytes.
- Capture cross-mechanism constraints (e.g., AES-GCM IV length) as validation helpers in `pkcs11:crypto`.

## Attribute Handling
- Determine whether to expose attribute length metadata separately to support lazy reads (`CK_UNAVAILABLE_INFORMATION`).
- Evaluate adding a `partial` flag to `pkcs11:core/attribute-value` to signal truncated attributes due to `buffer-too-small`.
- Review certificate-related attributes (X_509 vs WTLS) and map to structured records in `pkcs11:object` or `pkcs11:util`.

## Resource Semantics
- Confirm whether object resources should retain the owning session reference to enforce same-session usage or allow cross-session reuse for R/O tokens.
- Validate that returning `(object, object)` from `session::generate-key-pair` is supported by component tooling; fall back to separate calls if resource tuples prove difficult.
- Decide if `object.search::next` should return managed objects directly (requires resource lists) or stay with raw handles for simplicity.
- Explore exposing a `session::reset-operation-state()` helper mirroring `C_CloseAllSessions` semantics for state cleanup.

## Host Adapter Strategy
- Prototype a Rust host adapter using `wasmtime` components to validate resource drop semantics and error mapping.
- Define an abstraction for loading PKCS#11 libraries (path discovery, initialization arguments, mutex callbacks).
- Investigate sandbox considerations: ensure host adapter zeroizes `credential::inline` buffers and respects `pin-provider::clear` callbacks.
- Plan integration tests against SoftHSM and a hardware token to confirm cross-vendor behavior.

## Documentation & Examples
- Author usage examples showing a Wasm component enumerating slots, logging in, and exporting certificates.
- Provide guidance on handling vendor extensions, including a registry or mapping file for mechanism/object IDs.
- Document expected error propagation patterns so consumers know when to retry vs abort.
