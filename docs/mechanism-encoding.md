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
| `tls-master-key-derive` | `CK_TLS_MASTER_KEY_DERIVE_PARAMS` | Copy `client/server_random` bytes from the WIT payload, set client version tuple, and zero intermediary buffers after the call. |
| `tls-key-mat` | `CK_TLS_KEY_MAT_PARAMS` | Mirror SSL3 layout but without MAC secrets in the struct; copy `random-info`, set key/MAC/IV widths, guard `is-export` flag. |
| `ssl3-key-mat` | `CK_SSL3_KEY_MAT_PARAMS` | Same encoding path as TLS but uses the SSL3 random data structure. |
| `tls12-master-key-derive` | `CK_TLS12_MASTER_KEY_DERIVE_PARAMS` | Set hash mechanism, copy randoms, and enforce TLS 1.2 PRF inputs. |
| `tls12-key-mat` | `CK_TLS12_KEY_MAT_PARAMS` | Include hash mechanism, set random data pointers, and honor export flag when building the final struct. |
| `x942-dh1-derive` | `CK_X9_42_DH1_DERIVE_PARAMS` | Copy `other-info` and `public_data`, set `kdf` mechanism, and reference `base-key` via handle. |
| `x942-mqv-derive` | `CK_X9_42_MQV_DERIVE_PARAMS` | Populate both public key handles, optional private data handle, and `other-info` buffer before calling into the token. |
| `raw` | vendor-defined | Pass bytes through untouched. |

## Parameter Record Reference

The WIT records live under `wit/pkcs11-crypto/crypto.wit`. Each record mirrors a published `CK_*_PARAMS` layout; adapters should treat the WIT record as the authoritative schema when marshalling data.

- **RSA OAEP / PSS**: `rsa-oaep-param` and `rsa-pss-param` fold the PKCS#1 v2.2 fields directly into the record. Hash and mask-generation identifiers stay as `mechanism-type` so the adapter can translate them into `CK_MECHANISM_TYPE` values without a bespoke enum, and salt lengths remain host-endian `u32`.
- **AES AEAD**: `aes-gcm-param` and `aes-ccm-param` contain raw byte vectors for IV/AAD/nonce data plus explicit tag-bit and MAC-length integers. Tokens that require IV sizes aligned to block boundaries should enforce that invariant when validating the record.
- **HKDF / PBKDF2**: `hkdf-param` embeds mode/hash enums along with optional salt/info buffers modeled after `CK_HKDF_PARAMS`. `pbkdf2-param` mirrors `CK_PKCS5_PBKD2_PARAMS` and should be paired with legacy DES/AES key templates when deriving new handles.
- **TLS/SSL key material**: `tls-master-key-derive-param`, `tls-key-mat-param`, `tls12-*` variants, and the SSL3 equivalents all expose the `random-info` blobs as simple byte vectors. The host copies those bytes into the packed `CK_*` structs and zeroizes the scratch arena after the call returns.
- **X9.42 DH / MQV**: `x942-dh1-derive-param` and `x942-mqv-derive-param` map 1:1 with the CK structs, including subordinate handles for base/private keys. The adapter validates that the referenced handles belong to the same session before dispatching to the driver.
- **CMS / vendor extensions**: `cms-sig-param` and the `raw(bytes)` variant cover the long tail. CMS sticks with handles for certificates and optional mechanism overrides, while `raw` should only be used when the provider's documentation cannot be captured cleanly in WIT.

## Serialization Helpers
- Implement a `MechanismEncoder` trait that consumes a WIT variant and produces an owned `EncodedMechanism { mech_type: CK_MECHANISM_TYPE, temp: Vec<u8>, mechanism: CK_MECHANISM }`.
- Every encoder stores structs in `temp` to keep pointers stable until the call completes. After the native call returns, the temp buffer is dropped automatically.
- For multi-struct layouts (e.g., HKDF uses nested structs), `temp` holds both the parent struct and any buffers (salt/info). A convenience helper should append each allocation and rebase internal pointers after the final push.

## Nested Parameter Strategy
- Favor explicit records for every `CK_*_PARAMS` definition so adapters avoid ad-hoc byte packing. The new TLS master/key-mat and X9.42 DH derive records follow this rule and keep the layout authoritative in WIT.
- For structures that reference subordinate buffers (e.g., OAEP source data, HKDF salt/info), require the guest to pass typed fields instead of raw byte arrays, then copy those slices into a single temporary arena before dispatching.
- Vendor extensions that truly have no structured representation should continue to flow through the `raw(bytes)` variant. Document the expected byte layout in `docs/provider-guides/<provider>.md` whenever one is introduced.

## Validation Rules
- Reject mismatched `mechanism-type` and `mechanism-parameter` combinations with `error-code::mechanism-param-invalid` before invoking the driver.
- Check length limits (e.g., GCM tag between 96 and 128 bits) according to the PKCS#11 spec; surface `error-code::template-inconsistent` when preconditions fail.
- For `raw` payloads, allow the guest to decide the exact byte layout but require non-empty buffers.

## Mechanism Appendix

| Mechanism | CKM value | Notes |
| --- | --- | --- |
| `CKM_EDDSA` | `0x00001057` | Required for Ed25519/Ed448 signature flows; add to registry once vendor modules expose it. |
| `CKM_EC_EDWARDS_KEY_PAIR_GEN` | `0x00001055` | Key-pair generator for EdDSA; SoftHSM currently exposes it under build flag `--enable-ed25519`. |
| `CKM_RSA_PKCS` | `0x00000000` | Classic PKCS#1 v1.5 RSA encrypt/decrypt/sign entry point; no parameters. |
| `CKM_RSA_PKCS_OAEP` | `0x00000009` | Uses `rsa-oaep-param`; enforce hash/MGF compatibility before passing to the token. |
| `CKM_RSA_PKCS_PSS` | `0x0000000D` | Requires `rsa-pss-param`; use the WIT salt-length field rather than inferring from key size. |
| `CKM_AES_GCM` | `0x00001087` | Parameterized by `aes-gcm-param`; tag bits must be a multiple of 8. |
| `CKM_AES_CCM` | `0x0000108A` | Parameterized by `aes-ccm-param`; SoftHSM limits nonce sizes to 7–13 bytes. |
| `CKM_CHACHA20_KEY_GEN` | `0x00001225` | Seeds ChaCha20 keys before calling into `chacha20-poly1305` streaming helpers. |
| `CKM_CHACHA20` | `0x00001226` | Symmetric cipher exposed alongside Poly1305 for detached MAC cases. |
| `CKM_CHACHA20_POLY1305` | `0x00004021` | AEAD helper used by modern tokens; parameterized by the `chacha20-poly1305` record. |
| `CKM_AES_KEY_WRAP` | `0x00001090` | Default AES key wrap (NIST AES-KW); no parameters unless using the SET OAEP variant. |
| `CKM_AES_KEY_WRAP_PAD` | `0x00001091` | Adds padding for non-multiple-of-64-bit payloads; watch for provider-specific bugs. |
| `CKM_X9_42_DH_KEY_PAIR_GEN` | `0x00000030` | Generates the base key pair for all X9.42 derivations. |
| `CKM_X9_42_DH_DERIVE` | `0x00000031` | Uses `x942-dh1-derive` parameters; ensure `other-info` matches TLS export format. |
| `CKM_X9_42_MQV_DERIVE` | `0x00000033` | Parameterized by the MQV record; enforce consistent handle ownership. |
| `CKM_TLS_PRE_MASTER_KEY_GEN` | `0x00000374` | Backs the `tls-pre-master-key-gen` record and sets up master key derivation. |
| `CKM_TLS_MASTER_KEY_DERIVE` | `0x00000375` | Consumes `tls-master-key-derive` parameters; reuse the same random seed structure as SSL3. |
| `CKM_TLS_KEY_AND_MAC_DERIVE` | `0x00000376` | Wired to `tls-key-mat` parameters for TLS 1.0/1.1 sessions. |
| `CKM_TLS12_MASTER_KEY_DERIVE` | `0x000003E0` | Uses the TLS 1.2 master record and hash selection fields. |
| `CKM_TLS12_KEY_AND_MAC_DERIVE` | `0x000003E1` | Relies on the TLS 1.2 key-mat record and its hash algorithm input. |
| `CKM_TLS_KDF` | `0x000003E2` | Relies on `tls12-kdf-param`; useful for TLS exporter style flows. |
| `CKM_VENDOR_DEFINED` | `0x80000000`–`0xFFFFFFFF` | Reserve this range for provider-specific additions; document any allocated IDs in the provider guides. |

Use `wit/pkcs11-constants/constants.wit` as the authoritative source when adding more rows. Include both the symbolic name and hex value so adapters can cross-check registry submissions before merging.
