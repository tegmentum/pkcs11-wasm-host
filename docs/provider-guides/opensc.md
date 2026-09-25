# OpenSC Provider Guide

OpenSC exposes smartcard-backed PKCS#11 tokens. Use this guide to configure the adapter when physical cards or virtual PC/SC devices are available.

## Environment Variables
- `OPENSC_MODULE`: Override path to `opensc-pkcs11.so` when the default system path is unavailable.
- `PCSC_SOCKET`: Path to the PC/SC daemon socket (e.g., `/var/run/pcscd/pcscd.comm`). Mount it into containers running the host adapter.
- `OPENSC_INTEGRATION=1`: Opt-in flag for CI jobs that have card access; tests are skipped when unset.
- `PKCS11_USER_PIN`: Optional PIN forwarded to `session::login`.

## Provisioning Steps
1. Install OpenSC and ensure `pcscd` is running.
2. Insert a card or connect a USB token supported by OpenSC.
3. Verify connectivity via `opensc-tool --card-info`.
4. Export `OPENSC_MODULE` if the shared library is outside default lookup paths.
5. For containerized tests, mount `/var/run/pcscd.comm` (or platform equivalent) and pass through USB devices as needed.

## Troubleshooting
- `CKR_TOKEN_NOT_PRESENT`: Check that `pcscd` sees the card and that no other application holds exclusive access.
- `CKR_PIN_INCORRECT`: Cards often have limited retries; consult vendor docs for lockout thresholds before scripting retries.
- Protected authentication path: OpenSC reports `CKF_PROTECTED_AUTHENTICATION_PATH` for some tokens. Use provider-backed PIN prompts rather than inline credentials.

## Roadmap Alignment
The roadmap entry tracks pending work: container recipes, certificate CRUD coverage, and protected auth-path prompts. Update both this guide and `docs/provider-integration-roadmap.md` after adding fixtures or CI gates.
