# Resource Lifecycles

The PKCS#11 component world relies on WIT resources to wrap native handles. This narrative sequence highlights the lifecycle and host callbacks for each major resource.

## Slot and Token Discovery
1. `slot-manager::initialize(config)` prepares the provider; host loads vendor PKCS#11 library and calls `C_Initialize` once.
2. `slot-manager::get-slot-list(token-present)` translates to `C_GetSlotList`; raw `CK_SLOT_ID` values map directly to `pkcs11:core/slot-id`.
3. `slot-manager::get-slot-info(slot-id)` pulls `C_GetSlotInfo` into a `pkcs11:core/slot-info` record.
4. `slot-manager::get-token-info(slot-id)` (invoked before session creation) calls `C_GetTokenInfo` and returns `pkcs11:core/token-info`.

## Session Lifecycle
1. `token::open-session(slot-id, flags)` issues `C_OpenSession`, returning a `session` resource encapsulating the `CK_SESSION_HANDLE`.
2. When the resource constructor succeeds the host registers a drop handler that will invoke `C_CloseSession` unless the guest explicitly called `session::close()`.
3. Optional login flow:
   - `session::login(user-type, pin)` performs `C_Login`.
   - Subsequent authenticated operations reuse the same `session` resource.
   - `session::logout()` issues `C_Logout` and returns the session to public state.
4. `session::close()` flushes pending state, cancels active operations (`C_CloseSession`), and marks the resource handle invalid on the host side.
5. Dropping a session without calling `close()` triggers the same cleanup logic via the host drop handler.

## Object Discovery and Management
1. `session::find-objects-init(template)` maps to `C_FindObjectsInit` and returns a short-lived `search` resource containing the `CK_SESSION_HANDLE` plus an iterator cursor.
2. `search::next(max)` repeatedly calls `C_FindObjects` until the requested count is satisfied or no more results. Handles are wrapped as `object` resources on demand.
3. Dropping the `search` resource or calling `search::finish()` ensures `C_FindObjectsFinal` is executed.
4. `session::create-object(template)` uses `C_CreateObject`, returning an `object` resource. The host stores the handle and session owner for cleanup.
5. `object::destroy()` wraps `C_DestroyObject` and either consumes the resource or marks it invalid.
6. Automatic drop on `object` invokes `C_DestroyObject` only when the resource was created transiently (e.g., generated key marked non-token). Persistent objects simply release the handle.

## Attribute Metadata Hygiene
1. Every attribute returned by `object::get-attributes` now carries a `length-hint` mirroring `ulValueLen`. Use this to decide if a follow-up `get-attributes` call should request a larger buffer or if the token returned `CK_UNAVAILABLE_INFORMATION`.
2. The `partial` flag toggles when the host detects truncated data (e.g., SoftHSM reports `CKR_BUFFER_TOO_SMALL`). Callers should treat `partial = true` as a retry signal and include the latest `length-hint` when resizing.
3. Templates you send to `create-object`/`set-attributes` can leave `length-hint` unset; the host adapter computes the byte width automatically. Always zeroize temporary buffers (labels, secrets) after populating the template.
4. Certificate fetches should check `(tag = CKA_VALUE, partial = true)` and reissue the query with a `max-size` equal to `length-hint` before decoding DER blobs into the guest.

## Credential Handling & Zeroization
1. All session credential flows (`login`, `login_vendor`, `init_pin`, `set_pin`) wrap `credential::inline` payloads in `Zeroizing<Vec<u8>>` so the memory is scrubbed as soon as the PKCS#11 call completes.
2. When the guest supplies a `pin-provider`, the adapter calls `provider.request_secret` to obtain the PIN, immediately invokes `pin-provider::clear`, and then forwards the zeroized buffer into the native driver.
3. `slot-manager::init-token` now copies the supplied SO PIN into a `Zeroizing<Vec<u8>>` before invoking `C_InitToken`, ensuring SO credentials never linger in host memory regardless of success or failure.
4. Hosts must avoid logging inline credentials; traces and debug logs include only slot/session identifiers and high-level status codes.

## Cryptographic Operations
1. Stateless one-shot calls (`session::encrypt`, `session::decrypt`, `session::sign`, `session::verify`, `session::digest`) translate to corresponding `C_*` functions, using `pkcs11:core/mechanism` for parameters, while `session::generate-random` and `session::seed-random` wrap the token RNG APIs.
2. Multi-part workflows expose dedicated resources:
   - `session::encrypt-init(mechanism, key)` -> `resource encryptor` encapsulating session + mechanism state; drop handler runs `C_EncryptFinal`/`C_EncryptInit` cancel semantics.
   - `encryptor::update(chunk)` -> `C_EncryptUpdate`.
   - `encryptor::final(max-size)` -> `C_EncryptFinal`.
   Similar pattern applies for decrypt, sign, verify, digest, and hybrid sign/verify-recover flows.
3. Host ensures only one active mechanism state per session as required by the spec; starting a new operation implicitly finalizes the previous one.

## Key Generation and Derivation
1. `session::generate-key` wraps `C_GenerateKey` and returns a managed `object` resource for the new key.
2. `session::generate-key-pair` performs `C_GenerateKeyPair`, delivering both public and private key resources to the guest.
3. `session::derive-key` wraps `C_DeriveKey`, ensuring derived handles are tracked for cleanup.
4. `session::wrap-key` and `session::unwrap-key` mirror the PKCS#11 wrapping flows, producing or consuming opaque byte payloads while enforcing mechanism parameter checks.

## Shutdown
1. Explicit `slot-manager::finalize()` calls `C_Finalize` when the last session is closed.
2. Dropping the world import triggers best-effort finalization; host logs unexpected active sessions for observability.

This lifecycle narrative will inform interface method ordering and documentation, and it highlights where host-side drop guards must release native resources.
