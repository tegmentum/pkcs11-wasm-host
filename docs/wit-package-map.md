# WIT Package Map

This document sketches the initial layout for a PKCS#11 component world expressed in WIT. Each package is scoped so it can be versioned, tested, and reused independently.

## Canonical Paths
Set `PKCS11_WIT_ROOT=$(pwd)/wit` before running `cargo build` or `cargo test` so the host adapter and guest fixtures consume the in-tree schemas. The table below links each package to its on-disk location and the Rust module that currently binds it.

| Package | Filesystem path | Host adapter module(s) | Notes |
| --- | --- | --- | --- |
| `pkcs11:core` | `wit/pkcs11-core/core.wit` | `host-adapter/src/lib.rs` (`bindings::pkcs11::core::core`) | Tracks enums, error codes, attribute metadata. Update in lockstep with `docs/mechanism-encoding.md`. |
| `pkcs11:buffer` | `wit/pkcs11-buffer/buffer.wit` | `host-adapter/src/lib.rs` (`Chunk`, `OutputBuffer`) | Shared by session/crypto streaming helpers; keep chunk semantics aligned with host `bindings`. |
| `pkcs11:token` | `wit/pkcs11-token/slot-manager.wit` | `host-adapter/src/lib.rs::slot_manager` | Slot list, token info, wait-for-slot-event. |
| `pkcs11:session` | `wit/pkcs11-session/session.wit` | `host-adapter/src/lib.rs::session_iface` | Sessions, RNG, crypto entry points, state serialization. |
| `pkcs11:object` | `wit/pkcs11-object/object.wit` | `host-adapter/src/lib.rs::object_iface` | Attribute CRUD, search resources. |
| `pkcs11:crypto` | `wit/pkcs11-crypto/crypto.wit` | `host-adapter/src/lib.rs::crypto_iface` | Mechanism parameter variant, multipart crypto resources. |
| `pkcs11:util` | `wit/pkcs11-util/util.wit` | `host-adapter/src/lib.rs::bindings::pkcs11::util::util` | Credentials, helper records. |
| `pkcs11:registry` | `wit/pkcs11-registry/provider-registry.wit` | `host-adapter/src/lib.rs::bindings::exports::pkcs11::registry` | Provider registration/export surface. |
| `pkcs11:world` | `wit/worlds/pkcs11.wit` | `host-adapter/src/lib.rs::Pkcs11Component` | Aggregates the interfaces above. |
| `wasm-pkcs11:guestsmoke` | `wit/guest-smoke/guestsmoke.wit` | `guest-smoke/src/lib.rs` | Reference integration component exercising slot/session flows. |

## pkcs11:core
- Common enums, flag sets, bitmasks, handles, and error variants.
- Shared records for provider metadata (slot info, token info, mechanism info).
- Lightweight helper types (e.g., `type version = record { major: u8, minor: u8 }`) plus typed attribute metadata (`attribute-value { payload, length-hint, partial }`) to preserve `CK_UNAVAILABLE_INFORMATION` semantics.

## pkcs11:buffer
- Canonical byte buffer aliases and fixed-length block records for mechanism parameters.
- Potential `resource data-slice` abstraction for zero-copy host views, plus the `chunk` record used by multipart encrypt/decrypt/digest and the dual-purpose update helpers.

## pkcs11:token
- Slot discovery and token metadata interfaces (`interface slot-manager`).
- Token capability queries (`interface token` exposed as a resource once a slot is opened).

## pkcs11:session
- `resource session` for authenticated operations.
- Grouped methods for login/logout, find objects, key management, and stateful crypto contexts, including the dual-purpose `*-update` flows for digest+encrypt, decrypt+digest, sign+encrypt, and decrypt+verify.

## pkcs11:object
- `resource object` with attribute read/write helpers.
- Template encoding helpers for create/copy/wrap operations.

## pkcs11:crypto
- Mechanism parameter records (`variant mechanism-param`) including TLS master/key-mat and X9.42 DH derivations so adapters never serialize raw bytes.
- Stateless helpers for key derivation inputs, signing/digesting utilities.

## pkcs11:util
- Cross-cutting helpers: ASN.1-ish dates, big integers, attribute template utilities.
- Optional imports for secure input or logging callbacks.

## pkcs11:world
- Top-level `world pkcs11` exporting slot/token/session/object/crypto interfaces.
- Future host imports for services like secure PIN entry, RNG seeding, or audit logging.

The `wit/` tree mirrors these namespaces so new teams can onboard quickly and tooling can auto-discover the modules.
