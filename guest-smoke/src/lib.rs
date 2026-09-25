#![no_main]

mod bindings {
    wit_bindgen::generate!({
        world: "wasm-pkcs11:guestsmoke/guestsmoke",
        path: [
            "../wit/pkcs11-buffer/buffer.wit",
            "../wit/pkcs11-core/core.wit",
            "../wit/pkcs11-crypto/crypto.wit",
            "../wit/pkcs11-object/object.wit",
            "../wit/pkcs11-util/util.wit",
            "../wit/pkcs11-session/session.wit",
            "../wit/pkcs11-token/slot-manager.wit",
            "../wit/pkcs11-registry/provider-registry.wit",
            "../wit/guest-smoke/guestsmoke.wit",
        ],
        generate_all,
    });
}

use bindings::pkcs11::buffer::buffer::Chunk;
use bindings::pkcs11::core::core::{
    Attribute, AttributePayload, AttributeTemplate, AttributeValue, ErrorCode, Mechanism,
    SessionFlags, UserType,
};
use bindings::pkcs11::session::session::Session;
use bindings::pkcs11::token::slot_manager;
use bindings::pkcs11::util::util::Credential;
use bindings::Guest;

type GuestResult<T> = Result<T, String>;

struct GuestComponent;

impl GuestComponent {
    fn map<T>(context: &str, result: Result<T, ErrorCode>) -> Result<T, String> {
        result.map_err(|code| format!("{context}: {:?}", code))
    }

    fn exercise_operation_state(session: &Session, mechanism_kind: u64) -> Result<(), String> {
        let mechanism = Mechanism {
            kind: mechanism_kind,
            parameter: None,
        };
        let expected = session
            .digest(&mechanism, STATE_TEST_DATA)
            .map_err(|code| format!("baseline digest failed: {:?}", code))?;
        let digester = session
            .digest_init(&mechanism)
            .map_err(|code| format!("digest-init failed: {:?}", code))?;
        let chunk = Chunk {
            data: STATE_TEST_DATA.to_vec(),
            final_: false,
        };
        digester
            .update(&chunk)
            .map_err(|code| format!("digest update failed: {:?}", code))?;

        match session.get_operation_state(4096) {
            Ok(state) => {
                if state.truncated {
                    let _ = digester.abort();
                    return Err("operation state truncated; increase buffer".into());
                }
                match session.set_operation_state(&state.data, None, None) {
                    Ok(_) => {}
                    Err(ErrorCode::FunctionNotSupported) => {
                        let _ = digester.abort();
                        return Ok(());
                    }
                    Err(code) => {
                        let _ = digester.abort();
                        return Err(format!("set-operation-state failed: {:?}", code));
                    }
                }

                let mut final_chunk = chunk;
                final_chunk.data.clear();
                final_chunk.final_ = true;
                digester
                    .update(&final_chunk)
                    .map_err(|code| format!("digest update final failed: {:?}", code))?;
                let final_digest = digester
                    .final_()
                    .map_err(|code| format!("digest final failed: {:?}", code))?;
                if final_digest != expected {
                    return Err("operation state round trip mismatch".into());
                }
                Ok(())
            }
            Err(ErrorCode::FunctionNotSupported) => {
                let _ = digester.abort();
                Ok(())
            }
            Err(code) => {
                let _ = digester.abort();
                Err(format!("get-operation-state failed: {:?}", code))
            }
        }
    }
}

fn module_path() -> Result<String, String> {
    std::env::var("SOFTHSM_LIB")
        .or_else(|_| std::env::var("PKCS11_MODULE_PATH"))
        .map_err(|_| {
            "Set SOFTHSM_LIB or PKCS11_MODULE_PATH before running the smoke test".to_string()
        })
}

fn optional_pin() -> Option<String> {
    std::env::var("PKCS11_USER_PIN").ok()
}

fn state_mechanism() -> Option<u64> {
    let raw = std::env::var("PKCS11_STATE_MECH").ok()?;
    if let Some(rest) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).ok()
    } else {
        raw.parse().ok()
    }
}

impl Guest for GuestComponent {
    fn run() -> GuestResult<()> {
        let module = module_path()?;
        let init_config = format!("module={module}");
        GuestComponent::map(
            "initialize",
            slot_manager::initialize(Some(&init_config)),
        )?;

        let result = (|| {
            let slots = GuestComponent::map("get_slot_list", slot_manager::get_slot_list(false))?;
            let slot = *slots
                .first()
                .ok_or_else(|| "no slots reported".to_string())?;

            GuestComponent::map("get_slot_info", slot_manager::get_slot_info(slot))?;
            GuestComponent::map("get_token_info", slot_manager::get_token_info(slot))?;
            let mechanisms =
                GuestComponent::map("get_mechanism_list", slot_manager::get_mechanism_list(slot))?;
            if let Some(mech) = mechanisms.first() {
                GuestComponent::map(
                    "get_mechanism_info",
                    slot_manager::get_mechanism_info(slot, *mech),
                )?;
            }

            let mut session_flags = SessionFlags::SERIAL_SESSION;
            session_flags |= SessionFlags::RW_SESSION;
            let session = GuestComponent::map(
                "open_session",
                slot_manager::open_session(slot, session_flags),
            )?;

            GuestComponent::map("session.get_info", session.get_info())?;

            let random =
                GuestComponent::map("session.generate_random", session.generate_random(16))?;
            if random.len() != 16 {
                return Err("RNG returned unexpected length".to_string());
            }

            if let Some(pin) = optional_pin() {
                let pin_bytes = pin.into_bytes();
                GuestComponent::map(
                    "session.login",
                    session.login(UserType::User, Credential::Inline(pin_bytes.clone())),
                )?;

                let data = b"wasm-pkcs11-guest".to_vec();
                let label = format!(
                    "wasm-guest-{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                );
                let template: AttributeTemplate = vec![
                    Attribute {
                        tag: CKA_CLASS,
                        value: attr(AttributePayload::Uint32(CKO_DATA)),
                    },
                    Attribute {
                        tag: CKA_TOKEN,
                        value: attr(AttributePayload::Boolean(false)),
                    },
                    Attribute {
                        tag: CKA_LABEL,
                        value: attr(AttributePayload::ByteString(label.clone().into_bytes())),
                    },
                    Attribute {
                        tag: CKA_VALUE,
                        value: attr(AttributePayload::ByteString(data.clone())),
                    },
                ];

                let object = GuestComponent::map(
                    "session.create_object",
                    session.create_object(&template),
                )?;
                let size = GuestComponent::map("object.get_size", object.get_size())?;
                if size != data.len() as u64 {
                    return Err("object size mismatch".into());
                }

                GuestComponent::map("object.destroy", object.destroy())?;
                let rsa_id = vec![0xA5, 0x5A];
                let rsa_label = format!("{label}-rsa");
                let rsa_keygen = Mechanism {
                    kind: CKM_RSA_PKCS_KEY_PAIR_GEN,
                    parameter: None,
                };
                let public_template = rsa_public_template(&rsa_label, &rsa_id);
                let private_template = rsa_private_template(&rsa_label, &rsa_id);
                let (public_key, private_key) = GuestComponent::map(
                    "session.generate_key_pair",
                    session.generate_key_pair(
                        &rsa_keygen,
                        &public_template,
                        &private_template,
                    ),
                )?;

                let rsa_mechanism = Mechanism {
                    kind: CKM_RSA_PKCS,
                    parameter: None,
                };
                let recover_payload = b"guest-rsa-recover".to_vec();
                let recovered = GuestComponent::map(
                    "session.sign_recover",
                    session.sign_recover(
                        &rsa_mechanism,
                        &private_key,
                        &recover_payload,
                        4096,
                    ),
                )?;
                if recovered.truncated || recovered.data != recover_payload {
                    return Err("sign_recover mismatch".into());
                }

                let verified = GuestComponent::map(
                    "session.verify_recover",
                    session.verify_recover(
                        &rsa_mechanism,
                        &public_key,
                        &recovered.data,
                        4096,
                    ),
                )?;
                if verified.truncated || verified.data != recover_payload {
                    return Err("verify_recover mismatch".into());
                }

                let digest_mech = Mechanism {
                    kind: CKM_SHA256,
                    parameter: None,
                };
                let digester =
                    GuestComponent::map("session.digest_init", session.digest_init(&digest_mech))?;
                GuestComponent::map(
                    "session.digest_key",
                    session.digest_key(&private_key),
                )?;
                let digest = GuestComponent::map("digester.final", digester.final_())?;
                if digest.len() != 32 {
                    return Err("digest_key produced unexpected length".into());
                }

                GuestComponent::map("public.destroy", public_key.destroy())?;
                GuestComponent::map("private.destroy", private_key.destroy())?;

                GuestComponent::map("session.logout", session.logout())?;
            }

            if let Some(mech) = state_mechanism() {
                GuestComponent::exercise_operation_state(&session, mech)?;
            }

            GuestComponent::map("session.close", session.close())?;
            Ok(())
        })();

        let finalize_result = GuestComponent::map("finalize", slot_manager::finalize());

        match (result, finalize_result) {
            (Err(test_err), Err(finalize_err)) => Err(format!(
                "test failed ({test_err}) and finalize also failed ({finalize_err})"
            )),
            (Err(test_err), _) => Err(test_err),
            (_, Err(finalize_err)) => Err(finalize_err),
            (Ok(_), Ok(_)) => Ok(()),
        }
    }
}

bindings::export!(GuestComponent with_types_in bindings);

fn attr(payload: AttributePayload) -> AttributeValue {
    AttributeValue {
        payload,
        length_hint: None,
        partial: false,
    }
}

fn rsa_public_template(label: &str, id: &[u8]) -> AttributeTemplate {
    vec![
        Attribute {
            tag: CKA_CLASS,
            value: attr(AttributePayload::Uint32(CKO_PUBLIC_KEY)),
        },
        Attribute {
            tag: CKA_TOKEN,
            value: attr(AttributePayload::Boolean(false)),
        },
        Attribute {
            tag: CKA_LABEL,
            value: attr(AttributePayload::ByteString(label.as_bytes().to_vec())),
        },
        Attribute {
            tag: CKA_ID,
            value: attr(AttributePayload::ByteString(id.to_vec())),
        },
        Attribute {
            tag: CKA_KEY_TYPE,
            value: attr(AttributePayload::Uint32(CKK_RSA)),
        },
        Attribute {
            tag: CKA_MODULUS_BITS,
            value: attr(AttributePayload::Uint32(2048)),
        },
        Attribute {
            tag: CKA_PUBLIC_EXPONENT,
            value: attr(AttributePayload::ByteString(vec![1, 0, 1])),
        },
        Attribute {
            tag: CKA_VERIFY,
            value: attr(AttributePayload::Boolean(true)),
        },
        Attribute {
            tag: CKA_VERIFY_RECOVER,
            value: attr(AttributePayload::Boolean(true)),
        },
    ]
}

fn rsa_private_template(label: &str, id: &[u8]) -> AttributeTemplate {
    vec![
        Attribute {
            tag: CKA_CLASS,
            value: attr(AttributePayload::Uint32(CKO_PRIVATE_KEY)),
        },
        Attribute {
            tag: CKA_TOKEN,
            value: attr(AttributePayload::Boolean(false)),
        },
        Attribute {
            tag: CKA_LABEL,
            value: attr(AttributePayload::ByteString(label.as_bytes().to_vec())),
        },
        Attribute {
            tag: CKA_ID,
            value: attr(AttributePayload::ByteString(id.to_vec())),
        },
        Attribute {
            tag: CKA_KEY_TYPE,
            value: attr(AttributePayload::Uint32(CKK_RSA)),
        },
        Attribute {
            tag: CKA_PRIVATE,
            value: attr(AttributePayload::Boolean(true)),
        },
        Attribute {
            tag: CKA_SENSITIVE,
            value: attr(AttributePayload::Boolean(false)),
        },
        Attribute {
            tag: CKA_EXTRACTABLE,
            value: attr(AttributePayload::Boolean(true)),
        },
        Attribute {
            tag: CKA_SIGN,
            value: attr(AttributePayload::Boolean(true)),
        },
        Attribute {
            tag: CKA_SIGN_RECOVER,
            value: attr(AttributePayload::Boolean(true)),
        },
    ]
}

const CKA_CLASS: u32 = 0x0000_0000;
const CKA_TOKEN: u32 = 0x0000_0001;
const CKA_LABEL: u32 = 0x0000_0003;
const CKA_VALUE: u32 = 0x0000_0011;
const CKA_KEY_TYPE: u32 = 0x0000_0100;
const CKA_PRIVATE: u32 = 0x0000_0002;
const CKA_SENSITIVE: u32 = 0x0000_0103;
const CKA_EXTRACTABLE: u32 = 0x0000_0162;
const CKA_SIGN: u32 = 0x0000_0108;
const CKA_SIGN_RECOVER: u32 = 0x0000_0109;
const CKA_VERIFY: u32 = 0x0000_010A;
const CKA_VERIFY_RECOVER: u32 = 0x0000_010B;
const CKA_ID: u32 = 0x0000_0102;
const CKA_MODULUS_BITS: u32 = 0x0000_0121;
const CKA_PUBLIC_EXPONENT: u32 = 0x0000_0122;
const CKO_DATA: u32 = 0x0000_0003;
const CKO_PUBLIC_KEY: u32 = 0x0000_0002;
const CKO_PRIVATE_KEY: u32 = 0x0000_0003;
const CKK_RSA: u32 = 0x0000_0000;
const CKM_RSA_PKCS_KEY_PAIR_GEN: u64 = 0x0000_0000;
const CKM_RSA_PKCS: u64 = 0x0000_0001;
const CKM_SHA256: u64 = 0x0000_0250;
const STATE_TEST_DATA: &[u8] = b"guest-op-state";
