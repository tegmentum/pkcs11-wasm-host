# WIT Package Map

This document sketches the initial layout for a PKCS#11 component world expressed in WIT. Each package is scoped so it can be versioned, tested, and reused independently.

## pkcs11:core
- Common enums, flag sets, bitmasks, handles, and error variants.
- Shared records for provider metadata (slot info, token info, mechanism info).
- Lightweight helper types (e.g., `type version = record { major: u8, minor: u8 }`).

## pkcs11:buffer
- Canonical byte buffer aliases and fixed-length block records for mechanism parameters.
- Potential `resource data-slice` abstraction for zero-copy host views.

## pkcs11:token
- Slot discovery and token metadata interfaces (`interface slot-manager`).
- Token capability queries (`interface token` exposed as a resource once a slot is opened).

## pkcs11:session
- `resource session` for authenticated operations.
- Grouped methods for login/logout, find objects, key management, and stateful crypto contexts.

## pkcs11:object
- `resource object` with attribute read/write helpers.
- Template encoding helpers for create/copy/wrap operations.

## pkcs11:crypto
- Mechanism parameter records (`variant mechanism-param`).
- Stateless helpers for key derivation inputs, signing/digesting utilities.

## pkcs11:util
- Cross-cutting helpers: ASN.1-ish dates, big integers, attribute template utilities.
- Optional imports for secure input or logging callbacks.

## pkcs11:world
- Top-level `world pkcs11` exporting slot/token/session/object/crypto interfaces.
- Future host imports for services like secure PIN entry, RNG seeding, or audit logging.

The `wit/` tree mirrors these namespaces so new teams can onboard quickly and tooling can auto-discover the modules.
