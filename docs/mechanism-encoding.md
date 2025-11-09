# Mechanism Encoding Strategy

This note defines how the host adapter translates between the strongly typed WIT `pkcs11:crypto/mechanism-parameter` variant and native PKCS#11 `CK_MECHANISM` structures.

## Overview
- The WIT layer always passes a `pkcs11:core/mechanism { type, parameter }` record.
- When `parameter` is `None`, the adapter emits a native `CK_MECHANISM` with `pParameter = NULL` and `ulParameterLen = 0`.
- When `parameter` is `Some(bytes)`, the adapter validates that the payload matches the expected struct layout for the associated `mechanism-type`. Guests may still opt-in to raw byte mode for vendor-defined mechanisms.

## Variant Mapping

| `mechanism-parameter` variant | Native struct | Encoding steps |
| --- | --- | --- |
| `empty` | none | reject if guest also supplies bytes, otherwise set `pParameter = NULL`. |
| `rsa-oaep` | `CK_RSA_PKCS_OAEP_PARAMS` | Build struct with hash/MGF IDs from `mechanism-type` → `CK_MECHANISM_TYPE`, allocate `source_data`, copy bytes, and set pointer/length fields. |
| `rsa-pss` | `CK_RSA_PKCS_PSS_PARAMS` | Map hash/MGF, set `ulSaltLen`. |
| `aes-gcm` | `CK_GCM_PARAMS` | Copy IV/AAD into contiguous buffer, set `pIv`, `ulIvLen`, `ulIvBits`, `pAAD`, `ulAADLen`, `ulTagBits`. |
| `aes-ccm` | `CK_CCM_PARAMS` | Copy nonce/AAD, set `pNonce`, `ulNonceLen`, `pAAD`, `ulAADLen`, `ulDataLen`, `ulMACLen`. |
| `chacha20-poly1305` | `CK_CHACHA20_POLY1305_PARAMS` | Copy nonce/AAD, set `pNonce`, `ulNonceLen`, `pAAD`, `ulAADLen`, `ulTagLen`. |
| `hkdf` | `CK_HKDF_PARAMS` + `CK_HKDF_DATA` | Allocate scratch buffers for salt/info, set `prfHashMechanism`, and encode mode flags. |
| `tls-prf` | `CK_TLS_PRF_PARAMS` | Copy label bytes (UTF-8), point to seed buffer, set `ulOutputLen`. |
| `raw` | vendor-defined | Pass bytes through untouched. |

## Serialization Helpers
- Implement a `MechanismEncoder` trait that consumes a WIT variant and produces an owned `EncodedMechanism { mech_type: CK_MECHANISM_TYPE, temp: Vec<u8>, mechanism: CK_MECHANISM }`.
- Every encoder stores structs in `temp` to keep pointers stable until the call completes. After the native call returns, the temp buffer is dropped automatically.
- For multi-struct layouts (e.g., HKDF uses nested structs), `temp` holds both the parent struct and any buffers (salt/info). A convenience helper should append each allocation and rebase internal pointers after the final push.

## Validation Rules
- Reject mismatched `mechanism-type` and `mechanism-parameter` combinations with `error-code::mechanism-param-invalid` before invoking the driver.
- Check length limits (e.g., GCM tag between 96 and 128 bits) according to the PKCS#11 spec; surface `error-code::template-inconsistent` when preconditions fail.
- For `raw` payloads, allow the guest to decide the exact byte layout but require non-empty buffers.

## Future Work
- Add encoders for X9.42 DH, TLS key material, and vendor-defined structs once their WIT record equivalents are defined.
- Share encoders with the guest side by generating reference tests that assert byte layouts against known-good values (SoftHSM vectors).
