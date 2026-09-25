# YubiHSM 2 Provider Guide

YubiHSM 2 devices expose a PKCS#11 interface through the `yubihsm-connector`. This guide covers connector setup, environment wiring, and test expectations.

## Environment Variables
- `YUBIHSM_CONNECTOR_URL`: HTTP endpoint for the connector (default `http://127.0.0.1:12345`).
- `YUBIHSM_AUTH_KEY`: Authentication key ID used for PKCS#11 logins. Store secrets outside the repo (e.g., `.env.local`).
- `YUBIHSM_INTEGRATION=1`: Enables YubiHSM-specific tests; unset by default to keep CI token-free.
- `PKCS11_USER_PIN`: Optional default password for `C_Login` when using role-based credentials.

## Provisioning Steps
1. Install `yubihsm-connector` and ensure it can reach the USB device or network-attached YubiHSM.
2. Create an auth key with the desired policies (wrap/unwrap, sign, etc.) using `yubihsm-shell` or vendor tooling.
3. Populate `configs/yubihsm2.yaml` with connector URL, auth key references, and capability notes.
4. Export `YUBIHSM_CONNECTOR_URL` and `YUBIHSM_AUTH_KEY` before running targeted tests.

## Troubleshooting
- Connector unreachable: verify the connector process is running and not bound to localhost-only when remote clients connect.
- `CKR_DEVICE_REMOVED`: Indicates the connector lost contact with the hardware; restart the connector and reinitialize the adapter.
- `CKR_PIN_LOCKED`: Role-based auth keys respect retry counters; reset via `yubihsm-shell` if lockouts occur during stress tests.

## Roadmap Alignment
Refer to `docs/provider-integration-roadmap.md` for status on connector stubs, key provisioning scripts, and coverage goals. Update this guide whenever new configuration fields or fixtures land.
