#![no_main]

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

use bindings::imports::pkcs11::core::core::{
    Attribute, AttributeTemplate, AttributeValue, ErrorCode, SessionFlags, UserType,
};
use bindings::imports::pkcs11::core::core::{Credential, SessionFlags, UserType, Attribute, AttributeTemplate, AttributeValue, ErrorCode};
use bindings::imports::pkcs11::token::slot_manager;
use bindings::exports::wasm_pkcs11::guestsmoke::guestsmoke::{Guest, Result as GuestResult};

struct GuestComponent;

impl GuestComponent {
    fn map<T>(context: &str, result: Result<T, ErrorCode>) -> Result<T, String> {
        result.map_err(|code| format!("{context}: {:?}", code))
    }
}

fn module_path() -> Result<String, String> {
    std::env::var("PKCS11_MODULE_PATH").map_err(|_| "PKCS11_MODULE_PATH not set".to_string())
}

fn optional_pin() -> Option<String> {
    std::env::var("PKCS11_USER_PIN").ok()
}

impl Guest for GuestComponent {
    fn run() -> GuestResult<()> {
        let module = module_path()?;
        GuestComponent::map(
            "initialize",
            slot_manager::initialize(Some(format!("module={module}"))),
        )?;

        let result = (|| {
            let slots = GuestComponent::map("get_slot_list", slot_manager::get_slot_list(false))?;
            let slot = *slots.first().ok_or_else(|| "no slots reported".to_string())?;

            GuestComponent::map("get_slot_info", slot_manager::get_slot_info(slot))?;
            GuestComponent::map("get_token_info", slot_manager::get_token_info(slot))?;
            let mechanisms = GuestComponent::map(
                "get_mechanism_list",
                slot_manager::get_mechanism_list(slot),
            )?;
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

            let random = GuestComponent::map("session.generate_random", session.generate_random(16))?;
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
                        value: AttributeValue::Uint32(CKO_DATA),
                    },
                    Attribute {
                        tag: CKA_TOKEN,
                        value: AttributeValue::Boolean(false),
                    },
                    Attribute {
                        tag: CKA_LABEL,
                        value: AttributeValue::ByteString(label.clone().into_bytes()),
                    },
                    Attribute {
                        tag: CKA_VALUE,
                        value: AttributeValue::ByteString(data.clone()),
                    },
                ];

                let object = GuestComponent::map(
                    "session.create_object",
                    session.create_object(template.clone()),
                )?;
                let size = GuestComponent::map("object.get_size", object.get_size())?;
                if size != data.len() as u64 {
                    return Err("object size mismatch".into());
                }

                GuestComponent::map("object.destroy", object.destroy())?;
                GuestComponent::map("session.logout", session.logout())?;
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

bindings::exports::wasm_pkcs11::guestsmoke::guestsmoke::export!(GuestComponent);

const CKA_CLASS: u32 = 0x0000_0000;
const CKA_TOKEN: u32 = 0x0000_0001;
const CKA_LABEL: u32 = 0x0000_0003;
const CKA_VALUE: u32 = 0x0000_0011;
const CKO_DATA: u32 = 0x0000_0003;
