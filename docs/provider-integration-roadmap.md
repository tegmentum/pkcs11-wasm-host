# Provider Integration Roadmap

## Priority Providers for Automation
- **SoftHSM v2**: Maintain as default CI target. Add provisioning script (`scripts/softhsm-setup.sh`) to create slots, import keys, and tear down state after tests. Publish registry metadata as `provider=softhsm` so guests can auto-register paths surfaced via `SOFTHSM_LIB`.
- Expose the module path via the `SOFTHSM_LIB` environment variable so smoke tests (guest and host) can autodetect the provider without editing configs.
- **OpenSC pkcs11.so**: Target smartcard tokens exposed via OpenSC. Provide containerized test harness that mounts `/var/run/pcscd.pipe` for card access and reuses SoftHSM fixtures when hardware is absent.
- **YubiHSM 2**: Use the `yubihsm-connector` in HTTP proxy mode. Package config template (`configs/yubihsm2.yaml`) with default auth key and audit options; mock connector responses under `tests/yubihsm/fixtures/` for CI. Registry entries must capture connector URL, auth key IDs, and transport hints so consumers can pre-provision state.

### Provider Deliverable Matrix
| Provider | Config string example | Setup artifacts | Env/registry knobs | Coverage & status |
| --- | --- | --- | --- | --- |
| SoftHSM v2 | `module=/usr/local/lib/softhsm/libsofthsm2.so,mutex=os` | `scripts/softhsm-setup.sh`, slot provisioning YAML under `configs/softhsm/`, `docs/provider-guides/softhsm.md` | `SOFTHSM_LIB`, `SOFTHSM2_CONF`, optional `PKCS11_STATE_MECH`, registry entry `provider=softhsm` | ✅ Smoke + regression (slot discovery, login, RNG, AES/RSA/ECC, wrap/unwrap, operation state). Next: multi-module coverage + `wait-for-slot-event`. |
| OpenSC | `module=/usr/local/lib/opensc-pkcs11.so token=opensc` | Container recipe with `pcscd`, troubleshooting guide in `docs/provider-guides/opensc.md`, sample `.opensc.conf` | `OPENSC_MODULE`, `PCSC_SOCKET`, registry entry `provider=opensc` with slot labels and serials | 🟡 Smoke (enumeration, login, cert export) behind `OPENSC_INTEGRATION=1`; to-do: CI card stub, certificate CRUD, protected auth-path prompts. |
| YubiHSM 2 | `module=/usr/local/lib/libyubihsm_pkcs11.dylib connector=http://127.0.0.1:12345` | Config template `configs/yubihsm2.yaml`, mock connector fixtures in `tests/yubihsm/`, demo SO/OP key material | `YUBIHSM_CONNECTOR_URL`, `YUBIHSM_AUTH_KEY`, registry entry `provider=yubihsm2` with connector metadata | 🔜 Focused flows (session auth, wrap/unwrap, signature) behind `YUBIHSM_INTEGRATION=1`; needs connector stub + automated key provisioning script. |

## Provider-Specific Quirks & Setup
- **SoftHSM**: Requires `SOFTHSM2_CONF` pointing at a writable token DB. CI nodes need `softhsm2-util --init-token` executed prior to tests.
- **OpenSC**: Ensure `pcscd` service is running. Document driver packages per OS; warn about exclusive access when other PC/SC clients run simultaneously.
- **YubiHSM 2**: Connector listens on `127.0.0.1:12345`; set `YUBIHSM_CONNECTOR_URL`. Store auth key references in `.env.local`; never commit derived keys.

## Cloud HSM Stubbing Plan
1. Define `CloudModuleClient` trait under `host-adapter/src/cloud.rs` to abstract AWS/Azure RPC calls.
2. Implement `MockCloudClient` returning canned slot/session data; back by JSON fixtures for deterministic tests.
3. Add feature flags (`cloud-aws`, `cloud-azure`) that swap in real SDK adapters when credentials are supplied.
4. Extend the integration test harness to accept `CLOUD_ENDPOINT` and skip hardware validation when unset.

## Documentation & Tracking
- Record provider setup in `docs/provider-guides/<provider>.md` as scripts mature.
- Add task list to the `host-adapter` GitHub project board once available, linking the script/config PRs.
- Capture vendor-specific issues in `docs/open-questions.md` for follow-up design discussions.
- Keep the PKCS#11 provider registry current; add new entries via the WIT `provider-registry` export so guests can discover freshly integrated modules.
- Document provider-specific behavior for module metadata (`C_GetInfo`/`C_GetTokenInfo`) so discrepancies in flag handling or memory limits are visible when populating the registry.
