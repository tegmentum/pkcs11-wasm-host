//! Prototype host adapter wiring the `pkcs11:world/pkcs11` WIT world into a Rust environment.

use std::collections::HashMap;
use std::env;
use std::ffi::c_void;
use std::ptr;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use libloading;
use log::info;
use parking_lot::lock_api::RawMutex as _;
use parking_lot::{Mutex, RawMutex};
use zeroize::Zeroizing;

/// Re-export generated bindings once `wit-bindgen` has run.
pub mod bindings {
    wit_bindgen::generate!({
        world: "pkcs11:host/pkcs11",
        generate_all,
        path: [
            "../wit/pkcs11-buffer/buffer.wit",
            "../wit/pkcs11-core/core.wit",
            "../wit/pkcs11-crypto/crypto.wit",
            "../wit/pkcs11-object/object.wit",
            "../wit/pkcs11-util/util.wit",
            "../wit/pkcs11-session/session.wit",
            "../wit/pkcs11-token/slot-manager.wit",
            "../wit/pkcs11-registry/provider-registry.wit",
            "../wit/worlds/pkcs11.wit",
        ],
    });
}

mod cloud;
mod loader;

use crate::loader::{FilesystemLoader, LoaderError, ModuleConfig, ModuleLoader, MutexPreference};
use bindings::exports::pkcs11::crypto::crypto as crypto_iface;
use bindings::exports::pkcs11::object::object as object_iface;
use bindings::exports::pkcs11::object::object::GuestObject;
use bindings::exports::pkcs11::registry::provider_registry;
use bindings::exports::pkcs11::session::session as session_iface;
use bindings::exports::pkcs11::token::slot_manager;
use bindings::pkcs11::buffer::buffer::Chunk;
use bindings::pkcs11::core::core::{
    Attribute as WitAttribute, AttributePayload, AttributeTemplate, AttributeValue, ErrorCode,
    Mechanism, MechanismFlags, MechanismInfo, MechanismType, ModuleInfo, ObjectHandle,
    OutputBuffer, SessionFlags as WitSessionFlags, SessionState as WitSessionState, SlotFlags,
    SlotInfo, TokenFlags, TokenInfo, UserType, VendorUserType, Version,
};
use bindings::pkcs11::util::util::Credential as WitCredential;

/// Shared context for the adapter. Holds global PKCS#11 module state.
#[derive(Clone)]
pub struct AdapterContext {
    inner: Arc<Mutex<NativePkcs11>>, // Native bindings and module handles
}

#[derive(Clone, Debug)]
pub struct AdapterConfigSummary {
    pub module_path: String,
    pub mutex_preference: MutexPreference,
    pub slot_filter: Option<u32>,
}

impl AdapterConfigSummary {
    fn from_loader(config: &ModuleConfig, preferred_slot: Option<u32>) -> Self {
        Self {
            module_path: config.module_path.display().to_string(),
            mutex_preference: config.mutex_preference,
            slot_filter: preferred_slot,
        }
    }
}

impl AdapterContext {
    fn new() -> Self {
        let loader: Arc<dyn ModuleLoader> = Arc::new(FilesystemLoader::default());
        Self {
            inner: Arc::new(Mutex::new(NativePkcs11::new(loader))),
        }
    }

    pub fn current_config(&self) -> Option<String> {
        self.inner.lock().current_config()
    }

    pub fn config_summary(&self) -> Option<AdapterConfigSummary> {
        self.inner.lock().config_summary()
    }

    /// Guarantee the module is loaded and `C_Initialize` has been called.
    pub fn ensure_initialized(&self, config: &str) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.load_module(config)?;
        guard.initialize()?;
        if let Some(summary) = guard.config_summary() {
            info!(
                "pkcs11 module initialized: path={} mutex={:?} slot_filter={:?}",
                summary.module_path, summary.mutex_preference, summary.slot_filter
            );
        }
        Ok(())
    }

    /// Finalize the module if it has been initialized.
    pub fn finalize(&self) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.finalize()
    }

    /// Retrieve the list of available slot identifiers.
    pub fn slot_list(&self, token_present: bool) -> Result<Vec<u32>, ErrorCode> {
        let guard = self.inner.lock();
        guard.get_slot_list(token_present)
    }

    /// Fetch any serialized operation state.
    pub fn get_operation_state(
        &self,
        handle: u32,
        max_size: u32,
    ) -> Result<OutputBuffer, ErrorCode> {
        let guard = self.inner.lock();
        guard.get_operation_state(handle, max_size)
    }

    /// Restore a serialized operation state.
    pub fn set_operation_state(
        &self,
        handle: u32,
        state: &[u8],
        encryption_key: Option<u32>,
        auth_key: Option<u32>,
    ) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.set_operation_state(handle, state, encryption_key, auth_key)
    }

    /// Fetch module metadata exposed via `C_GetInfo`.
    pub fn module_info(&self) -> Result<ModuleInfo, ErrorCode> {
        let guard = self.inner.lock();
        guard.get_info()
    }

    /// Fetch metadata about a specific slot identifier.
    pub fn slot_info(&self, slot: u32) -> Result<SlotInfo, ErrorCode> {
        let guard = self.inner.lock();
        guard.get_slot_info(slot)
    }

    /// Fetch token metadata for a slot.
    pub fn token_info(&self, slot: u32) -> Result<TokenInfo, ErrorCode> {
        let guard = self.inner.lock();
        guard.get_token_info(slot)
    }

    /// Wait for a slot insertion/removal event.
    pub fn wait_for_slot_event(
        &self,
        flags: slot_manager::WaitFlags,
    ) -> Result<slot_manager::SlotEvent, ErrorCode> {
        let mut guard = self.inner.lock();
        guard.wait_for_slot_event(flags)
    }

    /// Fetch the list of supported mechanisms for a slot.
    pub fn mechanism_list(&self, slot: u32) -> Result<Vec<MechanismType>, ErrorCode> {
        let guard = self.inner.lock();
        guard.get_mechanism_list(slot)
    }

    /// Fetch mechanism capability metadata for a slot.
    pub fn mechanism_info(
        &self,
        slot: u32,
        mechanism: MechanismType,
    ) -> Result<MechanismInfo, ErrorCode> {
        let guard = self.inner.lock();
        guard.get_mechanism_info(slot, mechanism)
    }

    /// Reset a token and set the Security Officer PIN.
    pub fn init_token(
        &self,
        slot: u32,
        so_pin: Option<String>,
        label: String,
    ) -> Result<(), ErrorCode> {
        let pin = so_pin.map(|pin| Zeroizing::new(pin.into_bytes()));
        let mut guard = self.inner.lock();
        guard.init_token(slot, pin.as_ref().map(|p| p.as_slice()), label)
    }

    /// Close all open sessions for a slot.
    pub fn close_all_sessions(&self, slot: u32) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.close_all_sessions(slot)
    }

    /// Open a new PKCS#11 session.
    pub fn open_session(&self, slot: u32, flags: WitSessionFlags) -> Result<u32, ErrorCode> {
        let mut guard = self.inner.lock();
        guard.open_session(slot, flags)
    }

    pub fn sign_recover(
        &self,
        handle: u32,
        mechanism: &Mechanism,
        key: u32,
        data: &[u8],
        out_max: u32,
    ) -> Result<OutputBuffer, ErrorCode> {
        let mut guard = self.inner.lock();
        guard.sign_recover(handle, mechanism, key, data, out_max)
    }

    pub fn verify_recover(
        &self,
        handle: u32,
        mechanism: &Mechanism,
        key: u32,
        signature: &[u8],
        out_max: u32,
    ) -> Result<OutputBuffer, ErrorCode> {
        let mut guard = self.inner.lock();
        guard.verify_recover(handle, mechanism, key, signature, out_max)
    }

    pub fn digest_key(&self, handle: u32, key: u32) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.digest_key(handle, key)
    }

    /// Close an individual session.
    pub fn close_session(&self, handle: u32) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.close_session(handle)
    }

    /// Fetch session info for a given handle.
    pub fn session_info(&self, handle: u32) -> Result<session_iface::SessionInfo, ErrorCode> {
        let guard = self.inner.lock();
        guard.session_info(handle)
    }

    /// Log into the token with the provided user type and credential.
    pub fn login(&self, handle: u32, user: UserType, secret: &[u8]) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.login(handle, user, secret)
    }

    /// Log into the token with a vendor-specific user type.
    pub fn login_vendor(&self, handle: u32, user: u32, secret: &[u8]) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.login_vendor(handle, user, secret)
    }

    /// Log out of the current session.
    pub fn logout(&self, handle: u32) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.logout(handle)
    }

    /// Initialize a normal user's PIN.
    pub fn init_pin(&self, handle: u32, new_pin: &[u8]) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.init_pin(handle, new_pin)
    }

    /// Update the current user's PIN.
    pub fn set_pin(&self, handle: u32, old_pin: &[u8], new_pin: &[u8]) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.set_pin(handle, old_pin, new_pin)
    }

    /// Request the token cancel the currently running function.
    pub fn cancel_function(&self, handle: u32) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.cancel_function(handle)
    }

    /// Provide additional random seed material.
    pub fn seed_random(&self, handle: u32, seed: &[u8]) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.seed_random(handle, seed)
    }

    /// Generate random bytes from the token RNG.
    pub fn generate_random(&self, handle: u32, len: u32) -> Result<Vec<u8>, ErrorCode> {
        let mut guard = self.inner.lock();
        guard.generate_random(handle, len)
    }

    /// Create a new object using the supplied attribute template.
    pub fn create_object(&self, handle: u32, template: &[WitAttribute]) -> Result<u32, ErrorCode> {
        let mut guard = self.inner.lock();
        guard.create_object(handle, template)
    }

    /// Copy an existing object with optional overrides.
    pub fn copy_object(
        &self,
        handle: u32,
        source: u32,
        template: &[WitAttribute],
    ) -> Result<u32, ErrorCode> {
        let mut guard = self.inner.lock();
        guard.copy_object(handle, source, template)
    }

    /// Destroy the given object handle.
    pub fn destroy_object(&self, handle: u32, object: u32) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.destroy_object(handle, object)
    }

    /// Set object attributes using the provided template.
    pub fn set_attributes(
        &self,
        handle: u32,
        object: u32,
        template: &[WitAttribute],
    ) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.set_attributes(handle, object, template)
    }

    /// Fetch object attributes identified by the provided tags.
    pub fn get_attributes(
        &self,
        handle: u32,
        object: u32,
        tags: &[u32],
    ) -> Result<Vec<WitAttribute>, ErrorCode> {
        let guard = self.inner.lock();
        guard.get_attributes(handle, object, tags)
    }

    pub fn generate_key(
        &self,
        handle: u32,
        mechanism: &Mechanism,
        template: &[WitAttribute],
    ) -> Result<u32, ErrorCode> {
        let mut guard = self.inner.lock();
        guard.generate_key(handle, mechanism, template)
    }

    pub fn generate_key_pair(
        &self,
        handle: u32,
        mechanism: &Mechanism,
        public_template: &[WitAttribute],
        private_template: &[WitAttribute],
    ) -> Result<(u32, u32), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.generate_key_pair(handle, mechanism, public_template, private_template)
    }

    pub fn derive_key(
        &self,
        handle: u32,
        base_key: u32,
        mechanism: &Mechanism,
        template: &[WitAttribute],
    ) -> Result<u32, ErrorCode> {
        let mut guard = self.inner.lock();
        guard.derive_key(handle, base_key, mechanism, template)
    }

    pub fn wrap_key(
        &self,
        handle: u32,
        mechanism: &Mechanism,
        wrapping_key: u32,
        key: u32,
    ) -> Result<Vec<u8>, ErrorCode> {
        let guard = self.inner.lock();
        guard.wrap_key(handle, mechanism, wrapping_key, key)
    }

    pub fn unwrap_key(
        &self,
        handle: u32,
        mechanism: &Mechanism,
        wrapping_key: u32,
        wrapped_key: &[u8],
        template: &[WitAttribute],
    ) -> Result<u32, ErrorCode> {
        let mut guard = self.inner.lock();
        guard.unwrap_key(handle, mechanism, wrapping_key, wrapped_key, template)
    }

    /// Begin an object search using the supplied template.
    pub fn find_objects_init(
        &self,
        handle: u32,
        template: &[WitAttribute],
    ) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.find_objects_init(handle, template)
    }

    /// Fetch the next batch of object handles from an active search.
    pub fn find_objects(&self, handle: u32, max: u32) -> Result<Vec<u32>, ErrorCode> {
        let guard = self.inner.lock();
        guard.find_objects(handle, max)
    }

    /// Finalize an active search operation.
    pub fn find_objects_final(&self, handle: u32) -> Result<(), ErrorCode> {
        let mut guard = self.inner.lock();
        guard.find_objects_final(handle)
    }
}

fn adapter() -> AdapterContext {
    static CONTEXT: OnceLock<AdapterContext> = OnceLock::new();
    CONTEXT.get_or_init(AdapterContext::default).clone()
}

impl Default for AdapterContext {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
struct ProviderRecord {
    id: u32,
    name: String,
    module_path: String,
    description: Option<String>,
    default_config: Option<String>,
    last_updated_ms: Option<u64>,
}

impl ProviderRecord {
    fn summary(&self) -> provider_registry::ProviderSummary {
        provider_registry::ProviderSummary {
            id: self.id,
            name: self.name.clone(),
            module_path: self.module_path.clone(),
            description: self.description.clone(),
            default_config: self.default_config.clone(),
            last_updated_ms: self.last_updated_ms,
        }
    }
}

/// In-memory registry mapping provider names to PKCS#11 module metadata.
#[derive(Default)]
struct ProviderRegistryState {
    providers: HashMap<String, ProviderRecord>,
    next_id: u32,
}

impl ProviderRegistryState {
    fn new() -> Self {
        Self {
            providers: HashMap::new(),
            next_id: 1,
        }
    }

    fn timestamp_ms() -> Option<u64> {
        SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| {
            let millis = d.as_millis();
            if millis > u64::MAX as u128 {
                u64::MAX
            } else {
                millis as u64
            }
        })
    }

    fn normalize_identifier(name: &str) -> Option<String> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_lowercase())
        }
    }

    fn register(
        &mut self,
        spec: provider_registry::ProviderSpec,
    ) -> Result<provider_registry::ProviderSummary, provider_registry::RegistryError> {
        let provider_registry::ProviderSpec {
            name,
            module_path,
            description,
            default_config,
        } = spec;

        let normalized = Self::normalize_identifier(&name)
            .ok_or(provider_registry::RegistryError::InvalidArgument)?;

        let canonical_name = name.trim();
        let canonical_module = module_path.trim();

        if canonical_module.is_empty() {
            return Err(provider_registry::RegistryError::InvalidArgument);
        }

        let timestamp = Self::timestamp_ms();

        if let Some(existing) = self.providers.get_mut(&normalized) {
            existing.name = canonical_name.to_string();
            existing.module_path = canonical_module.to_string();
            existing.description = description.clone();
            existing.default_config = default_config.clone();
            existing.last_updated_ms = timestamp;
            return Ok(existing.summary());
        }

        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);

        let record = ProviderRecord {
            id,
            name: canonical_name.to_string(),
            module_path: canonical_module.to_string(),
            description,
            default_config,
            last_updated_ms: timestamp,
        };

        self.providers.insert(normalized, record.clone());

        Ok(record.summary())
    }

    fn unregister(&mut self, name: String) -> Result<(), provider_registry::RegistryError> {
        let normalized = Self::normalize_identifier(&name)
            .ok_or(provider_registry::RegistryError::InvalidArgument)?;

        self.providers
            .remove(&normalized)
            .map(|_| ())
            .ok_or(provider_registry::RegistryError::NotFound)
    }

    fn list(&self) -> Vec<provider_registry::ProviderSummary> {
        let mut summaries: Vec<_> = self
            .providers
            .values()
            .map(ProviderRecord::summary)
            .collect();
        summaries.sort_by(|a, b| a.name.cmp(&b.name));
        summaries
    }

    fn find(
        &self,
        name: String,
    ) -> Result<provider_registry::ProviderSummary, provider_registry::RegistryError> {
        let normalized = Self::normalize_identifier(&name)
            .ok_or(provider_registry::RegistryError::InvalidArgument)?;

        self.providers
            .get(&normalized)
            .map(ProviderRecord::summary)
            .ok_or(provider_registry::RegistryError::NotFound)
    }
}

fn trim_ck_utf8(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let slice = &bytes[..end];
    let trimmed = slice
        .iter()
        .map(|b| *b as char)
        .collect::<String>()
        .trim()
        .to_string();
    trimmed
}

fn provider_registry() -> &'static Mutex<ProviderRegistryState> {
    static REGISTRY: OnceLock<Mutex<ProviderRegistryState>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(ProviderRegistryState::new()))
}

pub struct Pkcs11Component;

impl provider_registry::Guest for Pkcs11Component {
    fn register_provider(
        spec: provider_registry::ProviderSpec,
    ) -> Result<provider_registry::ProviderSummary, provider_registry::RegistryError> {
        let mut guard = provider_registry().lock();
        guard.register(spec)
    }

    fn unregister_provider(name: String) -> Result<(), provider_registry::RegistryError> {
        let mut guard = provider_registry().lock();
        guard.unregister(name)
    }

    fn list_providers() -> Vec<provider_registry::ProviderSummary> {
        let guard = provider_registry().lock();
        guard.list()
    }

    fn find_provider(
        name: String,
    ) -> Result<provider_registry::ProviderSummary, provider_registry::RegistryError> {
        let guard = provider_registry().lock();
        guard.find(name)
    }
}

fn version_from_ck(version: ffi::CK_VERSION) -> Version {
    Version {
        major: version.major,
        minor: version.minor,
    }
}

fn slot_flags_from_ck(flags: ffi::CK_FLAGS) -> SlotFlags {
    let mut result = SlotFlags::empty();
    if flags & ffi::CKF_TOKEN_PRESENT != 0 {
        result |= SlotFlags::TOKEN_PRESENT;
    }
    if flags & ffi::CKF_REMOVABLE_DEVICE != 0 {
        result |= SlotFlags::REMOVABLE_DEVICE;
    }
    if flags & ffi::CKF_HW_SLOT != 0 {
        result |= SlotFlags::HW_SLOT;
    }
    result
}

fn token_flags_from_ck(flags: ffi::CK_FLAGS) -> TokenFlags {
    let mut result = TokenFlags::empty();
    if flags & ffi::CKF_RNG != 0 {
        result |= TokenFlags::RNG;
    }
    if flags & ffi::CKF_WRITE_PROTECTED != 0 {
        result |= TokenFlags::WRITE_PROTECTED;
    }
    if flags & ffi::CKF_LOGIN_REQUIRED != 0 {
        result |= TokenFlags::LOGIN_REQUIRED;
    }
    if flags & ffi::CKF_USER_PIN_INITIALIZED != 0 {
        result |= TokenFlags::USER_PIN_INITIALIZED;
    }
    if flags & ffi::CKF_RESTORE_KEY_NOT_NEEDED != 0 {
        result |= TokenFlags::RESTORE_KEY_NOT_NEEDED;
    }
    if flags & ffi::CKF_CLOCK_ON_TOKEN != 0 {
        result |= TokenFlags::CLOCK_ON_TOKEN;
    }
    if flags & ffi::CKF_PROTECTED_AUTHENTICATION_PATH != 0 {
        result |= TokenFlags::PROTECTED_AUTHENTICATION_PATH;
    }
    if flags & ffi::CKF_DUAL_CRYPTO_OPERATIONS != 0 {
        result |= TokenFlags::DUAL_CRYPTO_OPERATIONS;
    }
    if flags & ffi::CKF_TOKEN_INITIALIZED != 0 {
        result |= TokenFlags::TOKEN_INITIALIZED;
    }
    if flags & ffi::CKF_SECONDARY_AUTHENTICATION != 0 {
        result |= TokenFlags::SECONDARY_AUTHENTICATION;
    }
    if flags & ffi::CKF_USER_PIN_COUNT_LOW != 0 {
        result |= TokenFlags::USER_PIN_COUNT_LOW;
    }
    if flags & ffi::CKF_USER_PIN_FINAL_TRY != 0 {
        result |= TokenFlags::USER_PIN_FINAL_TRY;
    }
    if flags & ffi::CKF_USER_PIN_LOCKED != 0 {
        result |= TokenFlags::USER_PIN_LOCKED;
    }
    if flags & ffi::CKF_USER_PIN_TO_BE_CHANGED != 0 {
        result |= TokenFlags::USER_PIN_TO_BE_CHANGED;
    }
    if flags & ffi::CKF_SO_PIN_COUNT_LOW != 0 {
        result |= TokenFlags::SO_PIN_COUNT_LOW;
    }
    if flags & ffi::CKF_SO_PIN_FINAL_TRY != 0 {
        result |= TokenFlags::SO_PIN_FINAL_TRY;
    }
    if flags & ffi::CKF_SO_PIN_LOCKED != 0 {
        result |= TokenFlags::SO_PIN_LOCKED;
    }
    if flags & ffi::CKF_SO_PIN_TO_BE_CHANGED != 0 {
        result |= TokenFlags::SO_PIN_TO_BE_CHANGED;
    }
    if flags & ffi::CKF_ERROR_STATE != 0 {
        result |= TokenFlags::ERROR_STATE;
    }
    result
}

fn mechanism_flags_from_ck(flags: ffi::CK_FLAGS) -> MechanismFlags {
    let mut result = MechanismFlags::empty();
    if flags & ffi::CKF_HW != 0 {
        result |= MechanismFlags::HW;
    }
    if flags & ffi::CKF_ENCRYPT != 0 {
        result |= MechanismFlags::ENCRYPT;
    }
    if flags & ffi::CKF_DECRYPT != 0 {
        result |= MechanismFlags::DECRYPT;
    }
    if flags & ffi::CKF_DIGEST != 0 {
        result |= MechanismFlags::DIGEST;
    }
    if flags & ffi::CKF_SIGN != 0 {
        result |= MechanismFlags::SIGN;
    }
    if flags & ffi::CKF_SIGN_RECOVER != 0 {
        result |= MechanismFlags::SIGN_RECOVER;
    }
    if flags & ffi::CKF_VERIFY != 0 {
        result |= MechanismFlags::VERIFY;
    }
    if flags & ffi::CKF_VERIFY_RECOVER != 0 {
        result |= MechanismFlags::VERIFY_RECOVER;
    }
    if flags & ffi::CKF_GENERATE != 0 {
        result |= MechanismFlags::GENERATE;
    }
    if flags & ffi::CKF_GENERATE_KEY_PAIR != 0 {
        result |= MechanismFlags::GENERATE_KEY_PAIR;
    }
    if flags & ffi::CKF_WRAP != 0 {
        result |= MechanismFlags::WRAP;
    }
    if flags & ffi::CKF_UNWRAP != 0 {
        result |= MechanismFlags::UNWRAP;
    }
    if flags & ffi::CKF_DERIVE != 0 {
        result |= MechanismFlags::DERIVE;
    }
    if flags & ffi::CKF_EXTENSION != 0 {
        result |= MechanismFlags::EXTENSION;
    }
    result
}

fn ck_ulong_option(value: ffi::CK_ULONG) -> Option<u64> {
    if value == ffi::CK_UNAVAILABLE_INFORMATION {
        None
    } else {
        Some(value as u64)
    }
}

fn session_flags_to_ck(flags: WitSessionFlags) -> ffi::CK_FLAGS {
    let mut result: ffi::CK_FLAGS = 0;
    if flags.contains(WitSessionFlags::RW_SESSION) {
        result |= ffi::CKF_RW_SESSION;
    }
    if flags.contains(WitSessionFlags::SERIAL_SESSION) {
        result |= ffi::CKF_SERIAL_SESSION;
    }
    result
}

fn session_flags_from_ck(flags: ffi::CK_FLAGS) -> WitSessionFlags {
    let mut result = WitSessionFlags::empty();
    if flags & ffi::CKF_RW_SESSION != 0 {
        result |= WitSessionFlags::RW_SESSION;
    }
    if flags & ffi::CKF_SERIAL_SESSION != 0 {
        result |= WitSessionFlags::SERIAL_SESSION;
    }
    result
}

fn wait_flags_to_ck(flags: slot_manager::WaitFlags) -> ffi::CK_FLAGS {
    let mut result = 0;
    if flags.contains(slot_manager::WaitFlags::DONT_BLOCK) {
        result |= ffi::CKF_DONT_BLOCK;
    }
    result
}

fn session_state_from_ck(state: ffi::CK_STATE) -> WitSessionState {
    match state {
        ffi::CKS_RO_PUBLIC_SESSION => WitSessionState::RoPublicSession,
        ffi::CKS_RO_USER_FUNCTIONS => WitSessionState::RoUserFunctions,
        ffi::CKS_RW_PUBLIC_SESSION => WitSessionState::RwPublicSession,
        ffi::CKS_RW_USER_FUNCTIONS => WitSessionState::RwUserFunctions,
        ffi::CKS_RW_SO_FUNCTIONS => WitSessionState::RwSoFunctions,
        _ => WitSessionState::RoPublicSession,
    }
}

fn user_type_to_ck(user: UserType) -> ffi::CK_USER_TYPE {
    match user {
        UserType::So => ffi::CKU_SO,
        UserType::User => ffi::CKU_USER,
        UserType::ContextSpecific => ffi::CKU_CONTEXT_SPECIFIC,
    }
}

struct AttributeList {
    attrs: Vec<ffi::CK_ATTRIBUTE>,
    _storage: Vec<Vec<u8>>,
}

impl AttributeList {
    fn from_template(template: &[WitAttribute]) -> Result<Self, ErrorCode> {
        let mut attrs = Vec::with_capacity(template.len());
        let mut storage = Vec::with_capacity(template.len());

        for entry in template {
            let mut data = attribute_value_to_bytes(&entry.value)?;
            let ptr = if data.is_empty() {
                ptr::null_mut()
            } else {
                data.as_mut_ptr() as *mut c_void
            };
            attrs.push(ffi::CK_ATTRIBUTE {
                type_: entry.tag as ffi::CK_ATTRIBUTE_TYPE,
                p_value: ptr,
                ul_value_len: data.len() as ffi::CK_ULONG,
            });
            storage.push(data);
        }

        Ok(Self {
            attrs,
            _storage: storage,
        })
    }
}

struct MechanismHolder {
    mech: ffi::CK_MECHANISM,
    _parameter: Vec<u8>,
}

impl MechanismHolder {
    fn new(mechanism: &Mechanism) -> Self {
        let mut parameter = mechanism.parameter.clone().unwrap_or_default();
        let (ptr, len) = if parameter.is_empty() {
            (ptr::null_mut(), 0)
        } else {
            (
                parameter.as_mut_ptr() as *mut std::ffi::c_void,
                parameter.len() as ffi::CK_ULONG,
            )
        };
        Self {
            mech: ffi::CK_MECHANISM {
                mechanism: mechanism.kind as ffi::CK_MECHANISM_TYPE,
                p_parameter: ptr,
                ul_parameter_len: len,
            },
            _parameter: parameter,
        }
    }

    fn as_mut_ptr(&mut self) -> *mut ffi::CK_MECHANISM {
        &mut self.mech as *mut _
    }
}

fn to_ck_ulong(len: usize) -> Result<ffi::CK_ULONG, ErrorCode> {
    if len > ffi::CK_ULONG::MAX as usize {
        return Err(ErrorCode::BufferTooSmall);
    }
    Ok(len as ffi::CK_ULONG)
}

unsafe fn load_symbol<'lib, T>(
    lib: &'lib libloading::Library,
    name: &[u8],
) -> Result<libloading::Symbol<'lib, T>, ErrorCode> {
    lib.get(name).map_err(|_| ErrorCode::FunctionFailed)
}

fn attribute_value_to_bytes(value: &AttributeValue) -> Result<Vec<u8>, ErrorCode> {
    match &value.payload {
        AttributePayload::Boolean(v) => Ok(vec![*v as u8]),
        AttributePayload::Uint32(v) => Ok(v.to_ne_bytes().to_vec()),
        AttributePayload::Uint64(v) => Ok(v.to_ne_bytes().to_vec()),
        AttributePayload::ByteString(v) => Ok(v.clone()),
        AttributePayload::DateString(date) => Ok(date.as_bytes().to_vec()),
        AttributePayload::MechanismType(mech) => Ok(mech.to_ne_bytes().to_vec()),
        AttributePayload::KeyKind(kind) => Ok(kind.to_ne_bytes().to_vec()),
        AttributePayload::ObjectKind(class) => Ok(class.to_ne_bytes().to_vec()),
        AttributePayload::VendorBytes(v) => Ok(v.clone()),
    }
}

#[cfg(test)]
fn attribute_value_from_payload(payload: AttributePayload) -> AttributeValue {
    let length_hint = match &payload {
        AttributePayload::Boolean(_) => Some(1),
        AttributePayload::Uint32(_) => Some(4),
        AttributePayload::Uint64(_) => Some(8),
        AttributePayload::MechanismType(_) => Some(8),
        AttributePayload::KeyKind(_) => Some(4),
        AttributePayload::ObjectKind(_) => Some(4),
        AttributePayload::DateString(s) => Some(s.len() as u64),
        AttributePayload::ByteString(bytes) => Some(bytes.len() as u64),
        AttributePayload::VendorBytes(bytes) => Some(bytes.len() as u64),
    };
    AttributeValue {
        payload,
        length_hint,
        partial: false,
    }
}

const CKA_CLASS: u32 = 0x0000_0000;
const CKA_TOKEN: u32 = 0x0000_0001;
const CKA_PRIVATE: u32 = 0x0000_0002;
#[cfg(test)]
const CKA_LABEL: u32 = 0x0000_0003;
const CKA_TRUSTED: u32 = 0x0000_0086;
const CKA_MODULUS_BITS: u32 = 0x0000_0121;
const CKA_KEY_TYPE: u32 = 0x0000_0100;
const CKA_SENSITIVE: u32 = 0x0000_0103;
const CKA_ENCRYPT: u32 = 0x0000_0104;
const CKA_DECRYPT: u32 = 0x0000_0105;
const CKA_SIGN: u32 = 0x0000_0108;
const CKA_SIGN_RECOVER: u32 = 0x0000_0109;
const CKA_VERIFY: u32 = 0x0000_010A;
const CKA_VERIFY_RECOVER: u32 = 0x0000_010B;
const CKA_WRAP: u32 = 0x0000_0106;
const CKA_UNWRAP: u32 = 0x0000_0107;
const CKA_DERIVE: u32 = 0x0000_010C;
const CKA_EXTRACTABLE: u32 = 0x0000_0162;
const CKA_LOCAL: u32 = 0x0000_0163;
const CKA_NEVER_EXTRACTABLE: u32 = 0x0000_0164;
const CKA_ALWAYS_SENSITIVE: u32 = 0x0000_0165;
const CKA_MODIFIABLE: u32 = 0x0000_0170;
const CKA_COPYABLE: u32 = 0x0000_0171;
const CKA_DESTROYABLE: u32 = 0x0000_0172;
const CKA_ALWAYS_AUTHENTICATE: u32 = 0x0000_0202;
const CKA_VALUE_LEN: u32 = 0x0000_0161;
#[cfg(test)]
const CKA_ID: u32 = 0x0000_0102;
#[cfg(test)]
const CKA_PUBLIC_EXPONENT: u32 = 0x0000_0122;
#[cfg(test)]
const CKA_VALUE: u32 = 0x0000_0011;
#[cfg(test)]
const CKO_DATA: u32 = 0x0000_0003;
#[cfg(test)]
const CKO_PUBLIC_KEY: u32 = 0x0000_0002;
#[cfg(test)]
const CKO_PRIVATE_KEY: u32 = 0x0000_0003;
#[cfg(test)]
const CKK_RSA: u32 = 0x0000_0000;
#[cfg(test)]
const CKM_RSA_PKCS_KEY_PAIR_GEN: u64 = 0x0000_0000;
#[cfg(test)]
const CKM_RSA_PKCS: u64 = 0x0000_0001;
#[cfg(test)]
const CKM_SHA256: u64 = 0x0000_0250;

fn decode_attribute_payload(tag: u32, data: &[u8]) -> AttributePayload {
    if is_bool_attribute(tag) {
        return AttributePayload::Boolean(read_bool(data));
    }

    match tag {
        CKA_CLASS => read_u32(data)
            .map(AttributePayload::ObjectKind)
            .unwrap_or_else(|| AttributePayload::ByteString(data.to_vec())),
        CKA_KEY_TYPE => read_u32(data)
            .map(AttributePayload::KeyKind)
            .unwrap_or_else(|| AttributePayload::ByteString(data.to_vec())),
        CKA_MODULUS_BITS | CKA_VALUE_LEN => read_u64(data)
            .map(AttributePayload::Uint64)
            .or_else(|| read_u32(data).map(|v| AttributePayload::Uint64(v as u64)))
            .unwrap_or_else(|| AttributePayload::ByteString(data.to_vec())),
        _ => AttributePayload::ByteString(data.to_vec()),
    }
}

fn is_bool_attribute(tag: u32) -> bool {
    matches!(
        tag,
        CKA_TOKEN
            | CKA_PRIVATE
            | CKA_TRUSTED
            | CKA_SENSITIVE
            | CKA_ENCRYPT
            | CKA_DECRYPT
            | CKA_WRAP
            | CKA_UNWRAP
            | CKA_SIGN
            | CKA_SIGN_RECOVER
            | CKA_VERIFY
            | CKA_VERIFY_RECOVER
            | CKA_DERIVE
            | CKA_EXTRACTABLE
            | CKA_LOCAL
            | CKA_NEVER_EXTRACTABLE
            | CKA_ALWAYS_SENSITIVE
            | CKA_MODIFIABLE
            | CKA_COPYABLE
            | CKA_DESTROYABLE
            | CKA_ALWAYS_AUTHENTICATE
    )
}

fn read_bool(data: &[u8]) -> bool {
    data.first().copied().unwrap_or(0) != 0
}

fn read_u32(data: &[u8]) -> Option<u32> {
    if data.len() >= 4 {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&data[..4]);
        Some(u32::from_ne_bytes(buf))
    } else {
        None
    }
}

fn read_u64(data: &[u8]) -> Option<u64> {
    if data.len() >= 8 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[..8]);
        Some(u64::from_ne_bytes(buf))
    } else {
        None
    }
}

type HostMutexPrimitive = RawMutex;

unsafe fn host_mutex_from_ptr(ptr: *mut c_void) -> Option<&'static HostMutexPrimitive> {
    if ptr.is_null() {
        None
    } else {
        Some(&*(ptr as *mut HostMutexPrimitive))
    }
}

unsafe extern "C" fn create_host_mutex(mutex: *mut *mut c_void) -> ffi::CK_RV {
    if mutex.is_null() {
        return ffi::CKR_ARGUMENTS_BAD;
    }
    let raw = Box::new(HostMutexPrimitive::INIT);
    *mutex = Box::into_raw(raw) as *mut c_void;
    ffi::CKR_OK
}

unsafe extern "C" fn destroy_host_mutex(mutex: *mut c_void) -> ffi::CK_RV {
    if mutex.is_null() {
        return ffi::CKR_ARGUMENTS_BAD;
    }
    drop(Box::from_raw(mutex as *mut HostMutexPrimitive));
    ffi::CKR_OK
}

unsafe extern "C" fn lock_host_mutex(mutex: *mut c_void) -> ffi::CK_RV {
    if let Some(raw) = host_mutex_from_ptr(mutex) {
        raw.lock();
        ffi::CKR_OK
    } else {
        ffi::CKR_ARGUMENTS_BAD
    }
}

unsafe extern "C" fn unlock_host_mutex(mutex: *mut c_void) -> ffi::CK_RV {
    if let Some(raw) = host_mutex_from_ptr(mutex) {
        unsafe { raw.unlock() };
        ffi::CKR_OK
    } else {
        ffi::CKR_ARGUMENTS_BAD
    }
}

/// Native PKCS#11 module state guarded by a mutex.
struct NativePkcs11 {
    loader: Arc<dyn ModuleLoader>,
    module: Option<loader::ModuleHandle>,
    initialized: bool,
    preferred_slot: Option<u32>,
}

impl NativePkcs11 {
    fn new(loader: Arc<dyn ModuleLoader>) -> Self {
        Self {
            loader,
            module: None,
            initialized: false,
            preferred_slot: None,
        }
    }

    fn current_config(&self) -> Option<String> {
        self.module.as_ref().map(|handle| handle.config.raw.clone())
    }

    fn config_summary(&self) -> Option<AdapterConfigSummary> {
        self.module
            .as_ref()
            .map(|handle| AdapterConfigSummary::from_loader(&handle.config, self.preferred_slot))
    }

    fn module_library(&self) -> Result<&libloading::Library, ErrorCode> {
        self.module
            .as_ref()
            .map(|handle| &handle.library)
            .ok_or(ErrorCode::CryptokiNotInitialized)
    }

    fn library(&self) -> Result<&libloading::Library, ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        self.module_library()
    }

    fn load_module(&mut self, config: &str) -> Result<(), ErrorCode> {
        let parsed = self.loader.parse(config).map_err(ErrorCode::from)?;
        let preferred_slot = parsed
            .slot_filter
            .map(|slot| u32::try_from(slot).map_err(|_| ErrorCode::SlotIdInvalid))
            .transpose()?;
        let (must_reload, pref_changed) = match &self.module {
            Some(handle) => (
                handle.config.module_path != parsed.module_path,
                handle.config.mutex_preference != parsed.mutex_preference,
            ),
            None => (true, true),
        };
        let slot_changed = self.preferred_slot != preferred_slot;

        if self.initialized && (must_reload || pref_changed || slot_changed) {
            self.finalize()?;
        }

        if must_reload {
            let handle = self.loader.load(&parsed).map_err(ErrorCode::from)?;
            self.module = Some(handle);
            self.initialized = false;
        } else if let Some(current) = self.module.as_mut() {
            current.config = parsed;
            if pref_changed {
                self.initialized = false;
            }
        }
        self.preferred_slot = preferred_slot;

        Ok(())
    }

    fn initialize(&mut self) -> Result<(), ErrorCode> {
        if self.initialized {
            return Ok(());
        }

        let pref = self
            .module
            .as_ref()
            .map(|handle| handle.config.mutex_preference)
            .unwrap_or_default();
        let lib = self.module_library()?;

        unsafe {
            let c_initialize: libloading::Symbol<
                unsafe extern "C" fn(*const c_void) -> ffi::CK_RV,
            > = lib
                .get(b"C_Initialize\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let mut init_args = ffi::CK_C_INITIALIZE_ARGS::default();
            let args_ptr = match pref {
                MutexPreference::Auto | MutexPreference::OsThreads => {
                    init_args.flags = ffi::CKF_OS_LOCKING_OK;
                    &mut init_args as *mut _ as *const c_void
                }
                MutexPreference::None => {
                    init_args.create_mutex = Some(create_host_mutex);
                    init_args.destroy_mutex = Some(destroy_host_mutex);
                    init_args.lock_mutex = Some(lock_host_mutex);
                    init_args.unlock_mutex = Some(unlock_host_mutex);
                    &mut init_args as *mut _ as *const c_void
                }
            };
            let rv = c_initialize(args_ptr);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
        }

        self.initialized = true;
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), ErrorCode> {
        if !self.initialized {
            return Ok(());
        }
        let lib = self.module_library()?;
        unsafe {
            let c_finalize: libloading::Symbol<unsafe extern "C" fn(*const c_void) -> ffi::CK_RV> =
                lib.get(b"C_Finalize\0")
                    .map_err(|_| ErrorCode::FunctionFailed)?;
            let rv = c_finalize(std::ptr::null());
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
        }
        self.initialized = false;
        Ok(())
    }

    fn get_slot_list(&self, token_present: bool) -> Result<Vec<u32>, ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let c_get_slot_list: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_BBOOL,
                    *mut ffi::CK_SLOT_ID,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_GetSlotList\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;

            let mut count: ffi::CK_ULONG = 0;
            let rv = c_get_slot_list(
                token_present as ffi::CK_BBOOL,
                std::ptr::null_mut(),
                &mut count,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut slots = vec![0; count as usize];
            let rv = c_get_slot_list(
                token_present as ffi::CK_BBOOL,
                slots.as_mut_ptr(),
                &mut count,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut result = Vec::with_capacity(count as usize);
            for slot in slots.into_iter().take(count as usize) {
                if slot > u32::MAX as u64 {
                    return Err(ErrorCode::SlotIdInvalid);
                }
                result.push(slot as u32);
            }
            if let Some(preferred) = self.preferred_slot {
                if result.contains(&preferred) {
                    Ok(vec![preferred])
                } else {
                    Err(ErrorCode::SlotIdInvalid)
                }
            } else {
                Ok(result)
            }
        }
    }

    fn get_info(&self) -> Result<ModuleInfo, ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_get_info: libloading::Symbol<
                unsafe extern "C" fn(*mut ffi::CK_INFO) -> ffi::CK_RV,
            > = lib
                .get(b"C_GetInfo\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let mut info = ffi::CK_INFO::default();
            let rv = c_get_info(&mut info as *mut _);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(ModuleInfo {
                cryptoki_version: version_from_ck(info.cryptoki_version),
                manufacturer_id: trim_ck_utf8(&info.manufacturer_id),
                module_flags: info.flags,
                library_description: trim_ck_utf8(&info.library_description),
                library_version: version_from_ck(info.library_version),
            })
        }
    }

    fn get_slot_info(&self, slot: u32) -> Result<SlotInfo, ErrorCode> {
        self.ensure_slot_allowed(slot)?;
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_get_slot_info: libloading::Symbol<
                unsafe extern "C" fn(ffi::CK_SLOT_ID, *mut ffi::CK_SLOT_INFO) -> ffi::CK_RV,
            > = lib
                .get(b"C_GetSlotInfo\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let mut info = ffi::CK_SLOT_INFO::default();
            let rv = c_get_slot_info(slot as ffi::CK_SLOT_ID, &mut info as *mut _);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(SlotInfo {
                slot_description: trim_ck_utf8(&info.slot_description),
                manufacturer_id: trim_ck_utf8(&info.manufacturer_id),
                slot_flags: slot_flags_from_ck(info.flags),
                hardware_version: version_from_ck(info.hardware_version),
                firmware_version: version_from_ck(info.firmware_version),
            })
        }
    }

    fn get_token_info(&self, slot: u32) -> Result<TokenInfo, ErrorCode> {
        self.ensure_slot_allowed(slot)?;
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_get_token_info: libloading::Symbol<
                unsafe extern "C" fn(ffi::CK_SLOT_ID, *mut ffi::CK_TOKEN_INFO) -> ffi::CK_RV,
            > = lib
                .get(b"C_GetTokenInfo\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let mut info = ffi::CK_TOKEN_INFO::default();
            let rv = c_get_token_info(slot as ffi::CK_SLOT_ID, &mut info as *mut _);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            let utc = trim_ck_utf8(&info.utc_time);
            Ok(TokenInfo {
                label: trim_ck_utf8(&info.label),
                manufacturer_id: trim_ck_utf8(&info.manufacturer_id),
                model: trim_ck_utf8(&info.model),
                serial_number: trim_ck_utf8(&info.serial_number),
                token_flags: token_flags_from_ck(info.flags),
                max_session_count: info.max_session_count as u64,
                session_count: info.session_count as u64,
                max_rw_session_count: info.max_rw_session_count as u64,
                rw_session_count: info.rw_session_count as u64,
                max_pin_len: info.max_pin_len as u64,
                min_pin_len: info.min_pin_len as u64,
                total_public_memory: ck_ulong_option(info.total_public_memory),
                free_public_memory: ck_ulong_option(info.free_public_memory),
                total_private_memory: ck_ulong_option(info.total_private_memory),
                free_private_memory: ck_ulong_option(info.free_private_memory),
                hardware_version: version_from_ck(info.hardware_version),
                firmware_version: version_from_ck(info.firmware_version),
                utc_time: if utc.is_empty() { None } else { Some(utc) },
            })
        }
    }

    fn wait_for_slot_event(
        &mut self,
        flags: slot_manager::WaitFlags,
    ) -> Result<slot_manager::SlotEvent, ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.module_library()?;

        unsafe {
            let c_wait_for_slot_event: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_FLAGS,
                    *mut ffi::CK_SLOT_ID,
                    *mut c_void,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_WaitForSlotEvent\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let mut slot_id: ffi::CK_SLOT_ID = ffi::CK_INVALID_HANDLE;
            let rv = c_wait_for_slot_event(
                wait_flags_to_ck(flags),
                &mut slot_id as *mut _,
                std::ptr::null_mut(),
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            let slot = u32::try_from(slot_id).map_err(|_| ErrorCode::SlotIdInvalid)?;
            self.ensure_slot_allowed(slot)?;
            let info = self.get_slot_info(slot)?;
            let token_present = info.slot_flags.contains(SlotFlags::TOKEN_PRESENT);
            Ok(slot_manager::SlotEvent {
                slot,
                token_present,
            })
        }
    }

    fn get_mechanism_list(&self, slot: u32) -> Result<Vec<MechanismType>, ErrorCode> {
        self.ensure_slot_allowed(slot)?;
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_get_mechanism_list: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SLOT_ID,
                    *mut ffi::CK_MECHANISM_TYPE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_GetMechanismList\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;

            let mut count: ffi::CK_ULONG = 0;
            let rv =
                c_get_mechanism_list(slot as ffi::CK_SLOT_ID, std::ptr::null_mut(), &mut count);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut list: Vec<MechanismType> = vec![0; count as usize];
            let rv = c_get_mechanism_list(
                slot as ffi::CK_SLOT_ID,
                list.as_mut_ptr() as *mut ffi::CK_MECHANISM_TYPE,
                &mut count,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            list.truncate(count as usize);
            Ok(list)
        }
    }

    fn get_operation_state(&self, handle: u32, max_size: u32) -> Result<OutputBuffer, ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_get_operation_state: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_GetOperationState\0")?;
            let mut required: ffi::CK_ULONG = 0;
            let rv = c_get_operation_state(
                handle as ffi::CK_SESSION_HANDLE,
                ptr::null_mut(),
                &mut required,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut buffer = vec![0u8; required as usize];
            let mut actual = required;
            let rv = c_get_operation_state(
                handle as ffi::CK_SESSION_HANDLE,
                buffer.as_mut_ptr(),
                &mut actual,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            buffer.truncate(actual as usize);
            let mut truncated = false;
            if (max_size as u64) < actual as u64 {
                truncated = true;
                buffer.truncate(max_size as usize);
            }

            Ok(OutputBuffer {
                data: buffer,
                truncated,
            })
        }
    }

    fn set_operation_state(
        &mut self,
        handle: u32,
        state: &[u8],
        encryption_key: Option<u32>,
        auth_key: Option<u32>,
    ) -> Result<(), ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_set_operation_state: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                    ffi::CK_OBJECT_HANDLE,
                    ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_SetOperationState\0")?;
            let len = to_ck_ulong(state.len())?;
            let (ptr, len) = if state.is_empty() {
                (ptr::null(), 0)
            } else {
                (state.as_ptr(), len)
            };
            let enc_handle = encryption_key
                .map(|h| h as ffi::CK_OBJECT_HANDLE)
                .unwrap_or(ffi::CK_INVALID_HANDLE);
            let auth_handle = auth_key
                .map(|h| h as ffi::CK_OBJECT_HANDLE)
                .unwrap_or(ffi::CK_INVALID_HANDLE);
            let rv = c_set_operation_state(
                handle as ffi::CK_SESSION_HANDLE,
                ptr,
                len,
                enc_handle,
                auth_handle,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn get_mechanism_info(
        &self,
        slot: u32,
        mechanism: MechanismType,
    ) -> Result<MechanismInfo, ErrorCode> {
        self.ensure_slot_allowed(slot)?;
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_get_mechanism_info: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SLOT_ID,
                    ffi::CK_MECHANISM_TYPE,
                    *mut ffi::CK_MECHANISM_INFO,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_GetMechanismInfo\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let mut info = ffi::CK_MECHANISM_INFO::default();
            let rv = c_get_mechanism_info(
                slot as ffi::CK_SLOT_ID,
                mechanism as ffi::CK_MECHANISM_TYPE,
                &mut info as *mut _,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(MechanismInfo {
                min_key_size: info.min_key_size as u64,
                max_key_size: info.max_key_size as u64,
                mechanism_flags: mechanism_flags_from_ck(info.flags),
            })
        }
    }

    fn init_token(
        &mut self,
        slot: u32,
        so_pin: Option<&[u8]>,
        label: String,
    ) -> Result<(), ErrorCode> {
        self.ensure_slot_allowed(slot)?;
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_init_token: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SLOT_ID,
                    *const ffi::CK_UTF8CHAR,
                    ffi::CK_ULONG,
                    *const ffi::CK_UTF8CHAR,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_InitToken\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;

            let (pin_ptr, pin_len) = match so_pin {
                Some(bytes) if !bytes.is_empty() => (bytes.as_ptr(), bytes.len() as ffi::CK_ULONG),
                _ => (std::ptr::null(), 0),
            };

            let mut label_buf = [b' '; ffi::TOKEN_LABEL_LEN];
            for (dst, src) in label_buf.iter_mut().zip(label.as_bytes().iter()) {
                *dst = *src;
            }

            let rv = c_init_token(
                slot as ffi::CK_SLOT_ID,
                pin_ptr,
                pin_len,
                label_buf.as_ptr(),
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn close_all_sessions(&mut self, slot: u32) -> Result<(), ErrorCode> {
        self.ensure_slot_allowed(slot)?;
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_close_all_sessions: libloading::Symbol<
                unsafe extern "C" fn(ffi::CK_SLOT_ID) -> ffi::CK_RV,
            > = lib
                .get(b"C_CloseAllSessions\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let rv = c_close_all_sessions(slot as ffi::CK_SLOT_ID);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn login(&mut self, handle: u32, user: UserType, secret: &[u8]) -> Result<(), ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_login: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    ffi::CK_USER_TYPE,
                    *const ffi::CK_UTF8CHAR,
                    ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_Login\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;

            let (ptr, len) = if secret.is_empty() {
                (ptr::null(), 0)
            } else {
                (secret.as_ptr(), secret.len() as ffi::CK_ULONG)
            };

            let rv = c_login(
                handle as ffi::CK_SESSION_HANDLE,
                user_type_to_ck(user),
                ptr,
                len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn login_vendor(&mut self, handle: u32, user: u32, secret: &[u8]) -> Result<(), ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_login: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    ffi::CK_USER_TYPE,
                    *const ffi::CK_UTF8CHAR,
                    ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_Login\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;

            let (ptr, len) = if secret.is_empty() {
                (ptr::null(), 0)
            } else {
                (secret.as_ptr(), secret.len() as ffi::CK_ULONG)
            };

            let rv = c_login(
                handle as ffi::CK_SESSION_HANDLE,
                user as ffi::CK_USER_TYPE,
                ptr,
                len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn logout(&mut self, handle: u32) -> Result<(), ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_logout: libloading::Symbol<
                unsafe extern "C" fn(ffi::CK_SESSION_HANDLE) -> ffi::CK_RV,
            > = lib
                .get(b"C_Logout\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let rv = c_logout(handle as ffi::CK_SESSION_HANDLE);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn init_pin(&mut self, handle: u32, new_pin: &[u8]) -> Result<(), ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_init_pin: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_UTF8CHAR,
                    ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_InitPIN\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let (ptr, len) = if new_pin.is_empty() {
                (ptr::null(), 0)
            } else {
                (new_pin.as_ptr(), new_pin.len() as ffi::CK_ULONG)
            };
            let rv = c_init_pin(handle as ffi::CK_SESSION_HANDLE, ptr, len);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn set_pin(&mut self, handle: u32, old_pin: &[u8], new_pin: &[u8]) -> Result<(), ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_set_pin: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_UTF8CHAR,
                    ffi::CK_ULONG,
                    *const ffi::CK_UTF8CHAR,
                    ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_SetPIN\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let (old_ptr, old_len) = if old_pin.is_empty() {
                (ptr::null(), 0)
            } else {
                (old_pin.as_ptr(), old_pin.len() as ffi::CK_ULONG)
            };
            let (new_ptr, new_len) = if new_pin.is_empty() {
                (ptr::null(), 0)
            } else {
                (new_pin.as_ptr(), new_pin.len() as ffi::CK_ULONG)
            };
            let rv = c_set_pin(
                handle as ffi::CK_SESSION_HANDLE,
                old_ptr,
                old_len,
                new_ptr,
                new_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn cancel_function(&mut self, handle: u32) -> Result<(), ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_cancel_function: libloading::Symbol<
                unsafe extern "C" fn(ffi::CK_SESSION_HANDLE) -> ffi::CK_RV,
            > = lib
                .get(b"C_CancelFunction\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let rv = c_cancel_function(handle as ffi::CK_SESSION_HANDLE);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn seed_random(&mut self, handle: u32, seed: &[u8]) -> Result<(), ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_seed_random: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_SeedRandom\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let (ptr, len) = if seed.is_empty() {
                (ptr::null(), 0)
            } else {
                (seed.as_ptr(), seed.len() as ffi::CK_ULONG)
            };
            let rv = c_seed_random(handle as ffi::CK_SESSION_HANDLE, ptr, len);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn generate_random(&mut self, handle: u32, len: u32) -> Result<Vec<u8>, ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_generate_random: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_BYTE,
                    ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_GenerateRandom\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let mut buffer = vec![0u8; len as usize];
            let rv = c_generate_random(
                handle as ffi::CK_SESSION_HANDLE,
                buffer.as_mut_ptr(),
                len as ffi::CK_ULONG,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(buffer)
        }
    }

    fn ensure_slot_allowed(&self, slot: u32) -> Result<(), ErrorCode> {
        if let Some(preferred) = self.preferred_slot {
            if preferred != slot {
                return Err(ErrorCode::SlotIdInvalid);
            }
        }
        Ok(())
    }

    fn create_object(&mut self, handle: u32, template: &[WitAttribute]) -> Result<u32, ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let mut attrs = AttributeList::from_template(template)?;
        let lib = self.library()?;

        unsafe {
            let c_create_object: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_ATTRIBUTE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_CreateObject\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let mut object: ffi::CK_OBJECT_HANDLE = 0;
            let rv = c_create_object(
                handle as ffi::CK_SESSION_HANDLE,
                attrs.attrs.as_mut_ptr(),
                attrs.attrs.len() as ffi::CK_ULONG,
                &mut object as *mut _,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(object as u32)
        }
    }

    fn copy_object(
        &mut self,
        handle: u32,
        source: u32,
        template: &[WitAttribute],
    ) -> Result<u32, ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let mut attrs = AttributeList::from_template(template)?;
        let lib = self.library()?;

        unsafe {
            let c_copy_object: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    ffi::CK_OBJECT_HANDLE,
                    *mut ffi::CK_ATTRIBUTE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_CopyObject\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let mut object: ffi::CK_OBJECT_HANDLE = 0;
            let rv = c_copy_object(
                handle as ffi::CK_SESSION_HANDLE,
                source as ffi::CK_OBJECT_HANDLE,
                attrs.attrs.as_mut_ptr(),
                attrs.attrs.len() as ffi::CK_ULONG,
                &mut object as *mut _,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(object as u32)
        }
    }

    fn destroy_object(&mut self, handle: u32, object: u32) -> Result<(), ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_destroy_object: libloading::Symbol<
                unsafe extern "C" fn(ffi::CK_SESSION_HANDLE, ffi::CK_OBJECT_HANDLE) -> ffi::CK_RV,
            > = lib
                .get(b"C_DestroyObject\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let rv = c_destroy_object(
                handle as ffi::CK_SESSION_HANDLE,
                object as ffi::CK_OBJECT_HANDLE,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn set_attributes(
        &mut self,
        handle: u32,
        object: u32,
        template: &[WitAttribute],
    ) -> Result<(), ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let mut attrs = AttributeList::from_template(template)?;
        let lib = self.library()?;

        unsafe {
            let c_set_attribute_value: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    ffi::CK_OBJECT_HANDLE,
                    *mut ffi::CK_ATTRIBUTE,
                    ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_SetAttributeValue\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let rv = c_set_attribute_value(
                handle as ffi::CK_SESSION_HANDLE,
                object as ffi::CK_OBJECT_HANDLE,
                attrs.attrs.as_mut_ptr(),
                attrs.attrs.len() as ffi::CK_ULONG,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn get_attributes(
        &self,
        handle: u32,
        object: u32,
        tags: &[u32],
    ) -> Result<Vec<WitAttribute>, ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_get_attribute_value: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    ffi::CK_OBJECT_HANDLE,
                    *mut ffi::CK_ATTRIBUTE,
                    ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_GetAttributeValue\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;

            let mut attrs: Vec<ffi::CK_ATTRIBUTE> = tags
                .iter()
                .map(|tag| ffi::CK_ATTRIBUTE {
                    type_: *tag as ffi::CK_ATTRIBUTE_TYPE,
                    p_value: ptr::null_mut(),
                    ul_value_len: 0,
                })
                .collect();

            let rv = c_get_attribute_value(
                handle as ffi::CK_SESSION_HANDLE,
                object as ffi::CK_OBJECT_HANDLE,
                attrs.as_mut_ptr(),
                attrs.len() as ffi::CK_ULONG,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut buffers: Vec<Vec<u8>> = Vec::with_capacity(attrs.len());
            for attr in &mut attrs {
                let len = attr.ul_value_len as usize;
                if len == ffi::CK_UNAVAILABLE_INFORMATION as usize {
                    buffers.push(Vec::new());
                    attr.p_value = ptr::null_mut();
                } else {
                    let mut buf = vec![0u8; len];
                    attr.p_value = buf.as_mut_ptr() as *mut c_void;
                    buffers.push(buf);
                }
            }

            let rv = c_get_attribute_value(
                handle as ffi::CK_SESSION_HANDLE,
                object as ffi::CK_OBJECT_HANDLE,
                attrs.as_mut_ptr(),
                attrs.len() as ffi::CK_ULONG,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut result = Vec::with_capacity(attrs.len());
            for (idx, attr) in attrs.iter().enumerate() {
                let raw_len = attr.ul_value_len;
                let length = raw_len as usize;
                let bytes = if length == 0 || buffers[idx].is_empty() {
                    Vec::new()
                } else {
                    buffers[idx][..length.min(buffers[idx].len())].to_vec()
                };
                let payload = decode_attribute_payload(tags[idx], &bytes);
                let buffer_len = buffers[idx].len();
                let partial =
                    (buffer_len > 0 && length > buffer_len) || (buffer_len == 0 && length > 0);
                let length_hint = if raw_len == ffi::CK_UNAVAILABLE_INFORMATION {
                    None
                } else {
                    Some(raw_len as u64)
                };
                result.push(WitAttribute {
                    tag: tags[idx],
                    value: AttributeValue {
                        payload,
                        length_hint,
                        partial,
                    },
                });
            }

            Ok(result)
        }
    }

    fn find_objects_init(
        &mut self,
        handle: u32,
        template: &[WitAttribute],
    ) -> Result<(), ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let mut attrs = AttributeList::from_template(template)?;
        let lib = self.library()?;

        unsafe {
            let c_find_objects_init: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_ATTRIBUTE,
                    ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_FindObjectsInit\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let rv = c_find_objects_init(
                handle as ffi::CK_SESSION_HANDLE,
                attrs.attrs.as_mut_ptr(),
                attrs.attrs.len() as ffi::CK_ULONG,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn find_objects(&self, handle: u32, max: u32) -> Result<Vec<u32>, ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_find_objects: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_OBJECT_HANDLE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_FindObjects\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;

            let mut buffer = vec![0u64; max as usize];
            let mut count: ffi::CK_ULONG = 0;
            let rv = c_find_objects(
                handle as ffi::CK_SESSION_HANDLE,
                buffer.as_mut_ptr(),
                max as ffi::CK_ULONG,
                &mut count,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            buffer.truncate(count as usize);
            Ok(buffer.into_iter().map(|h| h as u32).collect())
        }
    }

    fn find_objects_final(&mut self, handle: u32) -> Result<(), ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_find_objects_final: libloading::Symbol<
                unsafe extern "C" fn(ffi::CK_SESSION_HANDLE) -> ffi::CK_RV,
            > = lib
                .get(b"C_FindObjectsFinal\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let rv = c_find_objects_final(handle as ffi::CK_SESSION_HANDLE);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn encrypt(
        &mut self,
        handle: u32,
        mechanism: &Mechanism,
        key: u32,
        plaintext: &[u8],
        out_max: u32,
    ) -> Result<OutputBuffer, ErrorCode> {
        let lib = self.library()?;
        let data_len = to_ck_ulong(plaintext.len())?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_encrypt_init: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_MECHANISM,
                    ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_EncryptInit\0")?;
            let rv = c_encrypt_init(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                key as ffi::CK_OBJECT_HANDLE,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let c_encrypt: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_Encrypt\0")?;

            let mut required_len: ffi::CK_ULONG = 0;
            let rv = c_encrypt(
                handle as ffi::CK_SESSION_HANDLE,
                plaintext.as_ptr(),
                data_len,
                ptr::null_mut(),
                &mut required_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut buffer = vec![0u8; required_len as usize];
            let mut actual_len = required_len;
            let rv = c_encrypt(
                handle as ffi::CK_SESSION_HANDLE,
                plaintext.as_ptr(),
                data_len,
                buffer.as_mut_ptr(),
                &mut actual_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            buffer.truncate(actual_len as usize);
            let mut truncated = false;
            if (out_max as u64) < actual_len as u64 {
                truncated = true;
                buffer.truncate(out_max as usize);
            }

            Ok(OutputBuffer {
                data: buffer,
                truncated,
            })
        }
    }

    fn decrypt(
        &mut self,
        handle: u32,
        mechanism: &Mechanism,
        key: u32,
        ciphertext: &[u8],
        out_max: u32,
    ) -> Result<OutputBuffer, ErrorCode> {
        let lib = self.library()?;
        let data_len = to_ck_ulong(ciphertext.len())?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_decrypt_init: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_MECHANISM,
                    ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_DecryptInit\0")?;
            let rv = c_decrypt_init(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                key as ffi::CK_OBJECT_HANDLE,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let c_decrypt: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_Decrypt\0")?;

            let mut required_len: ffi::CK_ULONG = 0;
            let rv = c_decrypt(
                handle as ffi::CK_SESSION_HANDLE,
                ciphertext.as_ptr(),
                data_len,
                ptr::null_mut(),
                &mut required_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut buffer = vec![0u8; required_len as usize];
            let mut actual_len = required_len;
            let rv = c_decrypt(
                handle as ffi::CK_SESSION_HANDLE,
                ciphertext.as_ptr(),
                data_len,
                buffer.as_mut_ptr(),
                &mut actual_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            buffer.truncate(actual_len as usize);
            let mut truncated = false;
            if (out_max as u64) < actual_len as u64 {
                truncated = true;
                buffer.truncate(out_max as usize);
            }

            Ok(OutputBuffer {
                data: buffer,
                truncated,
            })
        }
    }

    fn sign(
        &mut self,
        handle: u32,
        mechanism: &Mechanism,
        key: u32,
        message: &[u8],
    ) -> Result<Vec<u8>, ErrorCode> {
        let lib = self.library()?;
        let data_len = to_ck_ulong(message.len())?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_sign_init: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_MECHANISM,
                    ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_SignInit\0")?;
            let rv = c_sign_init(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                key as ffi::CK_OBJECT_HANDLE,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let c_sign: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_Sign\0")?;

            let mut required_len: ffi::CK_ULONG = 0;
            let rv = c_sign(
                handle as ffi::CK_SESSION_HANDLE,
                message.as_ptr(),
                data_len,
                ptr::null_mut(),
                &mut required_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut buffer = vec![0u8; required_len as usize];
            let mut actual_len = required_len;
            let rv = c_sign(
                handle as ffi::CK_SESSION_HANDLE,
                message.as_ptr(),
                data_len,
                buffer.as_mut_ptr(),
                &mut actual_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            buffer.truncate(actual_len as usize);
            Ok(buffer)
        }
    }

    fn verify(
        &mut self,
        handle: u32,
        mechanism: &Mechanism,
        key: u32,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), ErrorCode> {
        let lib = self.library()?;
        let data_len = to_ck_ulong(message.len())?;
        let sig_len = to_ck_ulong(signature.len())?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_verify_init: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_MECHANISM,
                    ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_VerifyInit\0")?;
            let rv = c_verify_init(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                key as ffi::CK_OBJECT_HANDLE,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let c_verify: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_Verify\0")?;

            let rv = c_verify(
                handle as ffi::CK_SESSION_HANDLE,
                message.as_ptr(),
                data_len,
                signature.as_ptr(),
                sig_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn digest(
        &mut self,
        handle: u32,
        mechanism: &Mechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, ErrorCode> {
        let lib = self.library()?;
        let data_len = to_ck_ulong(data.len())?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_digest_init: libloading::Symbol<
                unsafe extern "C" fn(ffi::CK_SESSION_HANDLE, *mut ffi::CK_MECHANISM) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_DigestInit\0")?;
            let rv = c_digest_init(handle as ffi::CK_SESSION_HANDLE, mech.as_mut_ptr());
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let c_digest: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_Digest\0")?;

            let mut required_len: ffi::CK_ULONG = 0;
            let rv = c_digest(
                handle as ffi::CK_SESSION_HANDLE,
                data.as_ptr(),
                data_len,
                ptr::null_mut(),
                &mut required_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut buffer = vec![0u8; required_len as usize];
            let mut actual_len = required_len;
            let rv = c_digest(
                handle as ffi::CK_SESSION_HANDLE,
                data.as_ptr(),
                data_len,
                buffer.as_mut_ptr(),
                &mut actual_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            buffer.truncate(actual_len as usize);
            Ok(buffer)
        }
    }

    fn sign_recover(
        &mut self,
        handle: u32,
        mechanism: &Mechanism,
        key: u32,
        data: &[u8],
        out_max: u32,
    ) -> Result<OutputBuffer, ErrorCode> {
        let lib = self.library()?;
        let data_len = to_ck_ulong(data.len())?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_sign_recover_init: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_MECHANISM,
                    ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_SignRecoverInit\0")?;
            let rv = c_sign_recover_init(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                key as ffi::CK_OBJECT_HANDLE,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let c_sign_recover: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_SignRecover\0")?;

            let mut required_len: ffi::CK_ULONG = 0;
            let rv = c_sign_recover(
                handle as ffi::CK_SESSION_HANDLE,
                data.as_ptr(),
                data_len,
                ptr::null_mut(),
                &mut required_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut buffer = vec![0u8; required_len as usize];
            let mut actual_len = required_len;
            let rv = c_sign_recover(
                handle as ffi::CK_SESSION_HANDLE,
                data.as_ptr(),
                data_len,
                buffer.as_mut_ptr(),
                &mut actual_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            buffer.truncate(actual_len as usize);
            let mut truncated = false;
            if (out_max as u64) < actual_len as u64 {
                truncated = true;
                buffer.truncate(out_max as usize);
            }

            Ok(OutputBuffer {
                data: buffer,
                truncated,
            })
        }
    }

    fn verify_recover(
        &mut self,
        handle: u32,
        mechanism: &Mechanism,
        key: u32,
        signature: &[u8],
        out_max: u32,
    ) -> Result<OutputBuffer, ErrorCode> {
        let lib = self.library()?;
        let sig_len = to_ck_ulong(signature.len())?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_verify_recover_init: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_MECHANISM,
                    ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_VerifyRecoverInit\0")?;
            let rv = c_verify_recover_init(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                key as ffi::CK_OBJECT_HANDLE,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let c_verify_recover: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_VerifyRecover\0")?;

            let mut required_len: ffi::CK_ULONG = 0;
            let rv = c_verify_recover(
                handle as ffi::CK_SESSION_HANDLE,
                signature.as_ptr(),
                sig_len,
                ptr::null_mut(),
                &mut required_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut buffer = vec![0u8; required_len as usize];
            let mut actual_len = required_len;
            let rv = c_verify_recover(
                handle as ffi::CK_SESSION_HANDLE,
                signature.as_ptr(),
                sig_len,
                buffer.as_mut_ptr(),
                &mut actual_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            buffer.truncate(actual_len as usize);
            let mut truncated = false;
            if (out_max as u64) < actual_len as u64 {
                truncated = true;
                buffer.truncate(out_max as usize);
            }

            Ok(OutputBuffer {
                data: buffer,
                truncated,
            })
        }
    }

    fn digest_key(&mut self, handle: u32, key: u32) -> Result<(), ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_digest_key: libloading::Symbol<
                unsafe extern "C" fn(ffi::CK_SESSION_HANDLE, ffi::CK_OBJECT_HANDLE) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_DigestKey\0")?;
            let rv = c_digest_key(
                handle as ffi::CK_SESSION_HANDLE,
                key as ffi::CK_OBJECT_HANDLE,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn generate_key(
        &mut self,
        handle: u32,
        mechanism: &Mechanism,
        template: &[WitAttribute],
    ) -> Result<u32, ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let mut attrs = AttributeList::from_template(template)?;
        let lib = self.library()?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_generate_key: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_MECHANISM,
                    *mut ffi::CK_ATTRIBUTE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_GenerateKey\0")?;
            let mut object = 0;
            let rv = c_generate_key(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                attrs.attrs.as_mut_ptr(),
                attrs.attrs.len() as ffi::CK_ULONG,
                &mut object,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(object as u32)
        }
    }

    fn generate_key_pair(
        &mut self,
        handle: u32,
        mechanism: &Mechanism,
        public_template: &[WitAttribute],
        private_template: &[WitAttribute],
    ) -> Result<(u32, u32), ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let mut public_attrs = AttributeList::from_template(public_template)?;
        let mut private_attrs = AttributeList::from_template(private_template)?;
        let lib = self.library()?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_generate_key_pair: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_MECHANISM,
                    *mut ffi::CK_ATTRIBUTE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_ATTRIBUTE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_OBJECT_HANDLE,
                    *mut ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_GenerateKeyPair\0")?;
            let mut public_handle = 0;
            let mut private_handle = 0;
            let rv = c_generate_key_pair(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                public_attrs.attrs.as_mut_ptr(),
                public_attrs.attrs.len() as ffi::CK_ULONG,
                private_attrs.attrs.as_mut_ptr(),
                private_attrs.attrs.len() as ffi::CK_ULONG,
                &mut public_handle,
                &mut private_handle,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok((public_handle as u32, private_handle as u32))
        }
    }

    fn derive_key(
        &mut self,
        handle: u32,
        base_key: u32,
        mechanism: &Mechanism,
        template: &[WitAttribute],
    ) -> Result<u32, ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let mut attrs = AttributeList::from_template(template)?;
        let lib = self.library()?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_derive_key: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_MECHANISM,
                    ffi::CK_OBJECT_HANDLE,
                    *mut ffi::CK_ATTRIBUTE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_DeriveKey\0")?;
            let mut new_handle = 0;
            let rv = c_derive_key(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                base_key as ffi::CK_OBJECT_HANDLE,
                attrs.attrs.as_mut_ptr(),
                attrs.attrs.len() as ffi::CK_ULONG,
                &mut new_handle,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(new_handle as u32)
        }
    }

    fn wrap_key(
        &self,
        handle: u32,
        mechanism: &Mechanism,
        wrapping_key: u32,
        key: u32,
    ) -> Result<Vec<u8>, ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_wrap_key: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_MECHANISM,
                    ffi::CK_OBJECT_HANDLE,
                    ffi::CK_OBJECT_HANDLE,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_WrapKey\0")?;
            let mut required: ffi::CK_ULONG = 0;
            let rv = c_wrap_key(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                wrapping_key as ffi::CK_OBJECT_HANDLE,
                key as ffi::CK_OBJECT_HANDLE,
                ptr::null_mut(),
                &mut required,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut buffer = vec![0u8; required as usize];
            let mut actual = required;
            let rv = c_wrap_key(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                wrapping_key as ffi::CK_OBJECT_HANDLE,
                key as ffi::CK_OBJECT_HANDLE,
                buffer.as_mut_ptr(),
                &mut actual,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            buffer.truncate(actual as usize);
            Ok(buffer)
        }
    }

    fn unwrap_key(
        &mut self,
        handle: u32,
        mechanism: &Mechanism,
        wrapping_key: u32,
        wrapped_key: &[u8],
        template: &[WitAttribute],
    ) -> Result<u32, ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let mut attrs = AttributeList::from_template(template)?;
        let lib = self.library()?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_unwrap_key: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_MECHANISM,
                    ffi::CK_OBJECT_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_ATTRIBUTE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_UnwrapKey\0")?;
            let len = to_ck_ulong(wrapped_key.len())?;
            let mut object = 0;
            let rv = c_unwrap_key(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                wrapping_key as ffi::CK_OBJECT_HANDLE,
                wrapped_key.as_ptr(),
                len,
                attrs.attrs.as_mut_ptr(),
                attrs.attrs.len() as ffi::CK_ULONG,
                &mut object,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(object as u32)
        }
    }

    fn get_object_size(&self, handle: u32, object: u32) -> Result<u64, ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let c_get_object_size: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    ffi::CK_OBJECT_HANDLE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_GetObjectSize\0")?;
            let mut size: ffi::CK_ULONG = 0;
            let rv = c_get_object_size(
                handle as ffi::CK_SESSION_HANDLE,
                object as ffi::CK_OBJECT_HANDLE,
                &mut size,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(size as u64)
        }
    }

    fn encrypt_init(
        &mut self,
        handle: u32,
        mechanism: &Mechanism,
        key: u32,
    ) -> Result<(), ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_encrypt_init: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_MECHANISM,
                    ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_EncryptInit\0")?;
            let rv = c_encrypt_init(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                key as ffi::CK_OBJECT_HANDLE,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn encrypt_update(&mut self, handle: u32, data: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        self.update_with_symbol(handle, data, b"C_EncryptUpdate\0")
    }

    fn encrypt_final(&mut self, handle: u32, out_max: u32) -> Result<Vec<u8>, ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let c_encrypt_final: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_EncryptFinal\0")?;

            let mut buffer = vec![0u8; out_max as usize];
            let mut len = out_max as ffi::CK_ULONG;
            let rv = c_encrypt_final(
                handle as ffi::CK_SESSION_HANDLE,
                if buffer.is_empty() {
                    ptr::null_mut()
                } else {
                    buffer.as_mut_ptr()
                },
                &mut len,
            );
            if rv == ffi::CKR_BUFFER_TOO_SMALL {
                let mut discard = 0;
                let _ = c_encrypt_final(
                    handle as ffi::CK_SESSION_HANDLE,
                    ptr::null_mut(),
                    &mut discard,
                );
                return Err(ErrorCode::BufferTooSmall);
            }
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            buffer.truncate(len as usize);
            Ok(buffer)
        }
    }

    fn encrypt_abort(&mut self, handle: u32) -> Result<(), ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let c_encrypt_final: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_EncryptFinal\0")?;
            let mut len: ffi::CK_ULONG = 0;
            let rv = c_encrypt_final(handle as ffi::CK_SESSION_HANDLE, ptr::null_mut(), &mut len);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn decrypt_init(
        &mut self,
        handle: u32,
        mechanism: &Mechanism,
        key: u32,
    ) -> Result<(), ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_decrypt_init: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_MECHANISM,
                    ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_DecryptInit\0")?;
            let rv = c_decrypt_init(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                key as ffi::CK_OBJECT_HANDLE,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn decrypt_update(&mut self, handle: u32, data: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        self.update_with_symbol(handle, data, b"C_DecryptUpdate\0")
    }

    fn digest_encrypt_update(&mut self, handle: u32, data: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        self.update_with_symbol(handle, data, b"C_DigestEncryptUpdate\0")
    }

    fn decrypt_digest_update(&mut self, handle: u32, data: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        self.update_with_symbol(handle, data, b"C_DecryptDigestUpdate\0")
    }

    fn sign_encrypt_update(&mut self, handle: u32, data: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        self.update_with_symbol(handle, data, b"C_SignEncryptUpdate\0")
    }

    fn decrypt_verify_update(&mut self, handle: u32, data: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        self.update_with_symbol(handle, data, b"C_DecryptVerifyUpdate\0")
    }

    fn update_with_symbol(
        &self,
        handle: u32,
        data: &[u8],
        symbol: &[u8],
    ) -> Result<Vec<u8>, ErrorCode> {
        let lib = self.library()?;
        let data_len = to_ck_ulong(data.len())?;

        unsafe {
            let update_fn: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, symbol)?;

            let mut required_len: ffi::CK_ULONG = 0;
            let rv = update_fn(
                handle as ffi::CK_SESSION_HANDLE,
                data.as_ptr(),
                data_len,
                ptr::null_mut(),
                &mut required_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut buffer = vec![0u8; required_len as usize];
            let mut actual_len = required_len;
            let mut rv = update_fn(
                handle as ffi::CK_SESSION_HANDLE,
                data.as_ptr(),
                data_len,
                if buffer.is_empty() {
                    ptr::null_mut()
                } else {
                    buffer.as_mut_ptr()
                },
                &mut actual_len,
            );
            if rv == ffi::CKR_BUFFER_TOO_SMALL {
                buffer.resize(actual_len as usize, 0);
                rv = update_fn(
                    handle as ffi::CK_SESSION_HANDLE,
                    data.as_ptr(),
                    data_len,
                    buffer.as_mut_ptr(),
                    &mut actual_len,
                );
            }
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            buffer.truncate(actual_len as usize);
            Ok(buffer)
        }
    }

    fn decrypt_final(&mut self, handle: u32, out_max: u32) -> Result<Vec<u8>, ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let c_decrypt_final: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_DecryptFinal\0")?;

            let mut buffer = vec![0u8; out_max as usize];
            let mut len = out_max as ffi::CK_ULONG;
            let rv = c_decrypt_final(
                handle as ffi::CK_SESSION_HANDLE,
                if buffer.is_empty() {
                    ptr::null_mut()
                } else {
                    buffer.as_mut_ptr()
                },
                &mut len,
            );
            if rv == ffi::CKR_BUFFER_TOO_SMALL {
                let mut discard = 0;
                let _ = c_decrypt_final(
                    handle as ffi::CK_SESSION_HANDLE,
                    ptr::null_mut(),
                    &mut discard,
                );
                return Err(ErrorCode::BufferTooSmall);
            }
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            buffer.truncate(len as usize);
            Ok(buffer)
        }
    }

    fn decrypt_abort(&mut self, handle: u32) -> Result<(), ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let c_decrypt_final: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_DecryptFinal\0")?;
            let mut len: ffi::CK_ULONG = 0;
            let rv = c_decrypt_final(handle as ffi::CK_SESSION_HANDLE, ptr::null_mut(), &mut len);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn sign_init(&mut self, handle: u32, mechanism: &Mechanism, key: u32) -> Result<(), ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_sign_init: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_MECHANISM,
                    ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_SignInit\0")?;
            let rv = c_sign_init(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                key as ffi::CK_OBJECT_HANDLE,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn sign_update(&mut self, handle: u32, data: &[u8]) -> Result<(), ErrorCode> {
        let lib = self.library()?;
        let data_len = to_ck_ulong(data.len())?;

        unsafe {
            let c_sign_update: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_SignUpdate\0")?;
            let rv = c_sign_update(handle as ffi::CK_SESSION_HANDLE, data.as_ptr(), data_len);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn sign_final(&mut self, handle: u32) -> Result<Vec<u8>, ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let c_sign_final: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_SignFinal\0")?;

            let mut required_len: ffi::CK_ULONG = 0;
            let rv = c_sign_final(
                handle as ffi::CK_SESSION_HANDLE,
                ptr::null_mut(),
                &mut required_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut buffer = vec![0u8; required_len as usize];
            let mut actual_len = required_len;
            let rv = c_sign_final(
                handle as ffi::CK_SESSION_HANDLE,
                if buffer.is_empty() {
                    ptr::null_mut()
                } else {
                    buffer.as_mut_ptr()
                },
                &mut actual_len,
            );
            if rv == ffi::CKR_BUFFER_TOO_SMALL {
                buffer.resize(actual_len as usize, 0);
                let rv_retry = c_sign_final(
                    handle as ffi::CK_SESSION_HANDLE,
                    buffer.as_mut_ptr(),
                    &mut actual_len,
                );
                if rv_retry != ffi::CKR_OK {
                    return Err(rv_to_error(rv_retry));
                }
            } else if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            buffer.truncate(actual_len as usize);
            Ok(buffer)
        }
    }

    fn sign_abort(&mut self, handle: u32) -> Result<(), ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let c_sign_final: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_SignFinal\0")?;
            let mut len: ffi::CK_ULONG = 0;
            let rv = c_sign_final(handle as ffi::CK_SESSION_HANDLE, ptr::null_mut(), &mut len);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn verify_init(
        &mut self,
        handle: u32,
        mechanism: &Mechanism,
        key: u32,
    ) -> Result<(), ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_verify_init: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_MECHANISM,
                    ffi::CK_OBJECT_HANDLE,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_VerifyInit\0")?;
            let rv = c_verify_init(
                handle as ffi::CK_SESSION_HANDLE,
                mech.as_mut_ptr(),
                key as ffi::CK_OBJECT_HANDLE,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn verify_update(&mut self, handle: u32, data: &[u8]) -> Result<(), ErrorCode> {
        let lib = self.library()?;
        let data_len = to_ck_ulong(data.len())?;

        unsafe {
            let c_verify_update: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_VerifyUpdate\0")?;
            let rv = c_verify_update(handle as ffi::CK_SESSION_HANDLE, data.as_ptr(), data_len);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn verify_final(&mut self, handle: u32, signature: &[u8]) -> Result<(), ErrorCode> {
        let lib = self.library()?;
        let sig_len = to_ck_ulong(signature.len())?;

        unsafe {
            let c_verify_final: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_VerifyFinal\0")?;
            let rv = c_verify_final(
                handle as ffi::CK_SESSION_HANDLE,
                if signature.is_empty() {
                    ptr::null()
                } else {
                    signature.as_ptr()
                },
                sig_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn verify_abort(&mut self, handle: u32) -> Result<(), ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let c_verify_final: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_VerifyFinal\0")?;
            let rv = c_verify_final(handle as ffi::CK_SESSION_HANDLE, ptr::null(), 0);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn digest_init(&mut self, handle: u32, mechanism: &Mechanism) -> Result<(), ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let mut mech = MechanismHolder::new(mechanism);
            let c_digest_init: libloading::Symbol<
                unsafe extern "C" fn(ffi::CK_SESSION_HANDLE, *mut ffi::CK_MECHANISM) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_DigestInit\0")?;
            let rv = c_digest_init(handle as ffi::CK_SESSION_HANDLE, mech.as_mut_ptr());
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn digest_update(&mut self, handle: u32, data: &[u8]) -> Result<(), ErrorCode> {
        let lib = self.library()?;
        let data_len = to_ck_ulong(data.len())?;

        unsafe {
            let c_digest_update: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *const ffi::CK_BYTE,
                    ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_DigestUpdate\0")?;
            let rv = c_digest_update(handle as ffi::CK_SESSION_HANDLE, data.as_ptr(), data_len);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn digest_final(&mut self, handle: u32) -> Result<Vec<u8>, ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let c_digest_final: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_DigestFinal\0")?;

            let mut required_len: ffi::CK_ULONG = 0;
            let rv = c_digest_final(
                handle as ffi::CK_SESSION_HANDLE,
                ptr::null_mut(),
                &mut required_len,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            let mut buffer = vec![0u8; required_len as usize];
            let mut actual_len = required_len;
            let rv = c_digest_final(
                handle as ffi::CK_SESSION_HANDLE,
                if buffer.is_empty() {
                    ptr::null_mut()
                } else {
                    buffer.as_mut_ptr()
                },
                &mut actual_len,
            );
            if rv == ffi::CKR_BUFFER_TOO_SMALL {
                buffer.resize(actual_len as usize, 0);
                let rv_retry = c_digest_final(
                    handle as ffi::CK_SESSION_HANDLE,
                    buffer.as_mut_ptr(),
                    &mut actual_len,
                );
                if rv_retry != ffi::CKR_OK {
                    return Err(rv_to_error(rv_retry));
                }
            } else if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }

            buffer.truncate(actual_len as usize);
            Ok(buffer)
        }
    }

    fn digest_abort(&mut self, handle: u32) -> Result<(), ErrorCode> {
        let lib = self.library()?;

        unsafe {
            let c_digest_final: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_BYTE,
                    *mut ffi::CK_ULONG,
                ) -> ffi::CK_RV,
            > = load_symbol(lib, b"C_DigestFinal\0")?;
            let mut len: ffi::CK_ULONG = 0;
            let rv = c_digest_final(handle as ffi::CK_SESSION_HANDLE, ptr::null_mut(), &mut len);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn open_session(&mut self, slot: u32, flags: WitSessionFlags) -> Result<u32, ErrorCode> {
        self.ensure_slot_allowed(slot)?;
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_open_session: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SLOT_ID,
                    ffi::CK_FLAGS,
                    *const c_void,
                    Option<unsafe extern "C" fn(ffi::CK_SESSION_HANDLE, ffi::CK_USER_TYPE)>,
                    *mut ffi::CK_SESSION_HANDLE,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_OpenSession\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;

            let mut handle: ffi::CK_SESSION_HANDLE = 0;
            let rv = c_open_session(
                slot as ffi::CK_SLOT_ID,
                session_flags_to_ck(flags),
                std::ptr::null(),
                None,
                &mut handle as *mut _,
            );
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(handle as u32)
        }
    }

    fn close_session(&mut self, handle: u32) -> Result<(), ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_close_session: libloading::Symbol<
                unsafe extern "C" fn(ffi::CK_SESSION_HANDLE) -> ffi::CK_RV,
            > = lib
                .get(b"C_CloseSession\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let rv = c_close_session(handle as ffi::CK_SESSION_HANDLE);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(())
        }
    }

    fn session_info(&self, handle: u32) -> Result<session_iface::SessionInfo, ErrorCode> {
        if !self.initialized {
            return Err(ErrorCode::CryptokiNotInitialized);
        }
        let lib = self.library()?;

        unsafe {
            let c_get_session_info: libloading::Symbol<
                unsafe extern "C" fn(
                    ffi::CK_SESSION_HANDLE,
                    *mut ffi::CK_SESSION_INFO,
                ) -> ffi::CK_RV,
            > = lib
                .get(b"C_GetSessionInfo\0")
                .map_err(|_| ErrorCode::FunctionFailed)?;
            let mut info = ffi::CK_SESSION_INFO::default();
            let rv = c_get_session_info(handle as ffi::CK_SESSION_HANDLE, &mut info as *mut _);
            if rv != ffi::CKR_OK {
                return Err(rv_to_error(rv));
            }
            Ok(session_iface::SessionInfo {
                slot: info.slot_id as u32,
                state: session_state_from_ck(info.state),
                session_flags: session_flags_from_ck(info.flags),
                device_error: info.device_error as u64,
            })
        }
    }
}

impl From<LoaderError> for ErrorCode {
    fn from(err: LoaderError) -> Self {
        match err {
            LoaderError::MissingModule
            | LoaderError::InvalidModule(_)
            | LoaderError::OutsideAllowedRoots { .. } => ErrorCode::ArgumentsBad,
            LoaderError::LoadFailure { .. } => ErrorCode::DeviceError,
        }
    }
}

/// Session resource implementation bridging to native PKCS#11 operations.
pub struct SessionInner {
    ctx: AdapterContext,
    handle: u32,
}

impl SessionInner {
    pub fn new(ctx: AdapterContext, handle: u32) -> Self {
        Self { ctx, handle }
    }

    fn credential_secret(credential: WitCredential) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        match credential {
            WitCredential::Inline(bytes) => Ok(Zeroizing::new(bytes)),
            WitCredential::Provider(provider) => {
                let secret = provider.request_secret(None, None);
                provider.clear();
                Ok(Zeroizing::new(secret))
            }
        }
    }
}

impl session_iface::GuestSession for SessionHost {
    fn close(&self) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.close())
    }

    fn get_info(&self) -> Result<session_iface::SessionInfo, ErrorCode> {
        self.with_inner(|inner| inner.get_info())
    }

    fn get_operation_state(&self, max_size: u32) -> Result<session_iface::OutputBuffer, ErrorCode> {
        self.with_inner(|inner| inner.get_operation_state(max_size))
    }

    fn set_operation_state(
        &self,
        state: Vec<u8>,
        encryption_key: Option<ObjectHandle>,
        auth_key: Option<ObjectHandle>,
    ) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.set_operation_state(state, encryption_key, auth_key))
    }

    fn login(&self, kind: UserType, secret: WitCredential) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.login(kind, secret))
    }

    fn login_vendor(&self, kind: VendorUserType, secret: WitCredential) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.login_vendor(kind, secret))
    }

    fn logout(&self) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.logout())
    }

    fn init_pin(&self, new_pin: WitCredential) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.init_pin(new_pin))
    }

    fn set_pin(&self, old_pin: WitCredential, new_pin: WitCredential) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.set_pin(old_pin, new_pin))
    }

    fn cancel_function(&self) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.cancel_function())
    }

    fn create_object(
        &self,
        template: AttributeTemplate,
    ) -> Result<session_iface::Object, ErrorCode> {
        self.with_inner(|inner| inner.create_object(template))
    }

    fn copy_object(
        &self,
        source: object_iface::ObjectBorrow<'_>,
        template: AttributeTemplate,
    ) -> Result<session_iface::Object, ErrorCode> {
        self.with_inner(|inner| inner.copy_object(source, template))
    }

    fn find_objects_init(
        &self,
        template: AttributeTemplate,
    ) -> Result<session_iface::Search, ErrorCode> {
        self.with_inner(|inner| inner.find_objects_init(template))
    }

    fn bind_object(&self, handle: ObjectHandle) -> Result<session_iface::Object, ErrorCode> {
        self.with_inner(|inner| inner.bind_object(handle))
    }

    fn encrypt(
        &self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
        plaintext: Vec<u8>,
        out_max: u32,
    ) -> Result<OutputBuffer, ErrorCode> {
        self.with_inner(|inner| inner.encrypt(mechanism, key, plaintext, out_max))
    }

    fn decrypt(
        &self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
        ciphertext: Vec<u8>,
        out_max: u32,
    ) -> Result<OutputBuffer, ErrorCode> {
        self.with_inner(|inner| inner.decrypt(mechanism, key, ciphertext, out_max))
    }

    fn sign(
        &self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, ErrorCode> {
        self.with_inner(|inner| inner.sign(mechanism, key, message))
    }

    fn verify(
        &self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.verify(mechanism, key, message, signature))
    }

    fn sign_recover(
        &self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
        data: Vec<u8>,
        out_max: u32,
    ) -> Result<OutputBuffer, ErrorCode> {
        self.with_inner(|inner| inner.sign_recover(mechanism, key, data, out_max))
    }

    fn verify_recover(
        &self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
        signature: Vec<u8>,
        out_max: u32,
    ) -> Result<OutputBuffer, ErrorCode> {
        self.with_inner(|inner| inner.verify_recover(mechanism, key, signature, out_max))
    }

    fn digest(&self, mechanism: Mechanism, data: Vec<u8>) -> Result<Vec<u8>, ErrorCode> {
        self.with_inner(|inner| inner.digest(mechanism, data))
    }

    fn digest_encrypt_update(&self, part: Chunk) -> Result<Vec<u8>, ErrorCode> {
        self.with_inner(|inner| inner.digest_encrypt_update(part))
    }

    fn decrypt_digest_update(&self, part: Chunk) -> Result<Vec<u8>, ErrorCode> {
        self.with_inner(|inner| inner.decrypt_digest_update(part))
    }

    fn sign_encrypt_update(&self, part: Chunk) -> Result<Vec<u8>, ErrorCode> {
        self.with_inner(|inner| inner.sign_encrypt_update(part))
    }

    fn decrypt_verify_update(&self, part: Chunk) -> Result<Vec<u8>, ErrorCode> {
        self.with_inner(|inner| inner.decrypt_verify_update(part))
    }

    fn encrypt_init(
        &self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
    ) -> Result<crypto_iface::Encryptor, ErrorCode> {
        self.with_inner(|inner| inner.encrypt_init(mechanism, key))
    }

    fn decrypt_init(
        &self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
    ) -> Result<crypto_iface::Decryptor, ErrorCode> {
        self.with_inner(|inner| inner.decrypt_init(mechanism, key))
    }

    fn sign_init(
        &self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
    ) -> Result<crypto_iface::Signer, ErrorCode> {
        self.with_inner(|inner| inner.sign_init(mechanism, key))
    }

    fn verify_init(
        &self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
    ) -> Result<crypto_iface::Verifier, ErrorCode> {
        self.with_inner(|inner| inner.verify_init(mechanism, key))
    }

    fn digest_init(&self, mechanism: Mechanism) -> Result<crypto_iface::Digester, ErrorCode> {
        self.with_inner(|inner| inner.digest_init(mechanism))
    }

    fn generate_key(
        &self,
        mechanism: Mechanism,
        template: AttributeTemplate,
    ) -> Result<session_iface::Object, ErrorCode> {
        self.with_inner(|inner| inner.generate_key(mechanism, template))
    }

    fn generate_key_pair(
        &self,
        mechanism: Mechanism,
        public_template: AttributeTemplate,
        private_template: AttributeTemplate,
    ) -> Result<(session_iface::Object, session_iface::Object), ErrorCode> {
        self.with_inner(|inner| {
            inner.generate_key_pair(mechanism, public_template, private_template)
        })
    }

    fn derive_key(
        &self,
        base_key: object_iface::ObjectBorrow<'_>,
        mechanism: Mechanism,
        template: AttributeTemplate,
    ) -> Result<session_iface::Object, ErrorCode> {
        self.with_inner(|inner| inner.derive_key(base_key, mechanism, template))
    }

    fn digest_key(&self, key: object_iface::ObjectBorrow<'_>) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.digest_key(key))
    }

    fn wrap_key(
        &self,
        mechanism: Mechanism,
        wrapping_key: object_iface::ObjectBorrow<'_>,
        key: object_iface::ObjectBorrow<'_>,
    ) -> Result<Vec<u8>, ErrorCode> {
        self.with_inner(|inner| inner.wrap_key(mechanism, wrapping_key, key))
    }

    fn unwrap_key(
        &self,
        mechanism: Mechanism,
        wrapping_key: object_iface::ObjectBorrow<'_>,
        wrapped_key: Vec<u8>,
        template: AttributeTemplate,
    ) -> Result<session_iface::Object, ErrorCode> {
        self.with_inner(|inner| inner.unwrap_key(mechanism, wrapping_key, wrapped_key, template))
    }

    fn seed_random(&self, seed: Vec<u8>) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.seed_random(seed))
    }

    fn generate_random(&self, len: u32) -> Result<Vec<u8>, ErrorCode> {
        self.with_inner(|inner| inner.generate_random(len))
    }
}

pub struct SessionHost {
    inner: Mutex<SessionInner>,
}

impl SessionHost {
    fn new(ctx: AdapterContext, handle: u32) -> Self {
        Self {
            inner: Mutex::new(SessionInner::new(ctx, handle)),
        }
    }

    fn with_inner<R>(
        &self,
        f: impl FnOnce(&mut SessionInner) -> Result<R, ErrorCode>,
    ) -> Result<R, ErrorCode> {
        let mut guard = self.inner.lock();
        f(&mut guard)
    }
}

impl session_iface::Guest for Pkcs11Component {
    type Session = SessionHost;
}

impl Drop for SessionInner {
    fn drop(&mut self) {
        let _ = self.ctx.close_session(self.handle);
    }
}

impl SessionInner {
    fn close(&mut self) -> Result<(), ErrorCode> {
        self.ctx.close_session(self.handle)
    }

    fn get_info(&mut self) -> Result<session_iface::SessionInfo, ErrorCode> {
        self.ctx.session_info(self.handle)
    }

    fn get_operation_state(
        &mut self,
        max_size: u32,
    ) -> Result<session_iface::OutputBuffer, ErrorCode> {
        self.ctx.get_operation_state(self.handle, max_size)
    }

    fn set_operation_state(
        &mut self,
        state: Vec<u8>,
        encryption_key: Option<ObjectHandle>,
        auth_key: Option<ObjectHandle>,
    ) -> Result<(), ErrorCode> {
        self.ctx
            .set_operation_state(self.handle, &state, encryption_key, auth_key)
    }

    fn login(&mut self, kind: UserType, secret: WitCredential) -> Result<(), ErrorCode> {
        let secret = Self::credential_secret(secret)?;
        self.ctx.login(self.handle, kind, secret.as_slice())
    }

    fn login_vendor(
        &mut self,
        kind: VendorUserType,
        secret: WitCredential,
    ) -> Result<(), ErrorCode> {
        let secret = Self::credential_secret(secret)?;
        self.ctx.login_vendor(self.handle, kind, secret.as_slice())
    }

    fn logout(&mut self) -> Result<(), ErrorCode> {
        self.ctx.logout(self.handle)
    }

    fn init_pin(&mut self, new_pin: WitCredential) -> Result<(), ErrorCode> {
        let new_pin = Self::credential_secret(new_pin)?;
        self.ctx.init_pin(self.handle, new_pin.as_slice())
    }

    fn set_pin(&mut self, old_pin: WitCredential, new_pin: WitCredential) -> Result<(), ErrorCode> {
        let old_pin = Self::credential_secret(old_pin)?;
        let new_pin = Self::credential_secret(new_pin)?;
        self.ctx
            .set_pin(self.handle, old_pin.as_slice(), new_pin.as_slice())
    }

    fn cancel_function(&mut self) -> Result<(), ErrorCode> {
        self.ctx.cancel_function(self.handle)
    }

    fn create_object(
        &mut self,
        template: AttributeTemplate,
    ) -> Result<session_iface::Object, ErrorCode> {
        let handle = self.ctx.create_object(self.handle, &template)?;
        Ok(session_iface::Object::new(ObjectHost::new(
            self.ctx.clone(),
            self.handle,
            handle,
        )))
    }

    fn copy_object(
        &mut self,
        source: object_iface::ObjectBorrow<'_>,
        template: AttributeTemplate,
    ) -> Result<session_iface::Object, ErrorCode> {
        let source_handle = source.get::<ObjectHost>().get_handle();
        let handle = self
            .ctx
            .copy_object(self.handle, source_handle, &template)?;
        Ok(session_iface::Object::new(ObjectHost::new(
            self.ctx.clone(),
            self.handle,
            handle,
        )))
    }

    fn find_objects_init(
        &mut self,
        template: AttributeTemplate,
    ) -> Result<session_iface::Search, ErrorCode> {
        self.ctx.find_objects_init(self.handle, &template)?;
        Ok(session_iface::Search::new(SearchHost::new(
            self.ctx.clone(),
            self.handle,
        )))
    }

    fn bind_object(&mut self, handle: u32) -> Result<session_iface::Object, ErrorCode> {
        Ok(session_iface::Object::new(ObjectHost::new(
            self.ctx.clone(),
            self.handle,
            handle,
        )))
    }

    fn encrypt(
        &mut self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
        plaintext: Vec<u8>,
        out_max: u32,
    ) -> Result<OutputBuffer, ErrorCode> {
        let key_handle = key.get::<ObjectHost>().get_handle();
        let result = {
            let mut guard = self.ctx.inner.lock();
            guard.encrypt(self.handle, &mechanism, key_handle, &plaintext, out_max)
        }?;
        Ok(result)
    }

    fn decrypt(
        &mut self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
        ciphertext: Vec<u8>,
        out_max: u32,
    ) -> Result<OutputBuffer, ErrorCode> {
        let key_handle = key.get::<ObjectHost>().get_handle();
        let result = {
            let mut guard = self.ctx.inner.lock();
            guard.decrypt(self.handle, &mechanism, key_handle, &ciphertext, out_max)
        }?;
        Ok(result)
    }

    fn sign(
        &mut self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, ErrorCode> {
        let key_handle = key.get::<ObjectHost>().get_handle();
        let signature = {
            let mut guard = self.ctx.inner.lock();
            guard.sign(self.handle, &mechanism, key_handle, &message)
        }?;
        Ok(signature)
    }

    fn verify(
        &mut self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), ErrorCode> {
        let key_handle = key.get::<ObjectHost>().get_handle();
        {
            let mut guard = self.ctx.inner.lock();
            guard.verify(self.handle, &mechanism, key_handle, &message, &signature)
        }
    }

    fn sign_recover(
        &mut self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
        data: Vec<u8>,
        out_max: u32,
    ) -> Result<OutputBuffer, ErrorCode> {
        let key_handle = key.get::<ObjectHost>().get_handle();
        let result = {
            let mut guard = self.ctx.inner.lock();
            guard.sign_recover(self.handle, &mechanism, key_handle, &data, out_max)
        }?;
        Ok(result)
    }

    fn verify_recover(
        &mut self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
        signature: Vec<u8>,
        out_max: u32,
    ) -> Result<OutputBuffer, ErrorCode> {
        let key_handle = key.get::<ObjectHost>().get_handle();
        let result = {
            let mut guard = self.ctx.inner.lock();
            guard.verify_recover(self.handle, &mechanism, key_handle, &signature, out_max)
        }?;
        Ok(result)
    }

    fn digest(&mut self, mechanism: Mechanism, data: Vec<u8>) -> Result<Vec<u8>, ErrorCode> {
        let digest = {
            let mut guard = self.ctx.inner.lock();
            guard.digest(self.handle, &mechanism, &data)
        }?;
        Ok(digest)
    }

    fn digest_encrypt_update(&mut self, part: Chunk) -> Result<Vec<u8>, ErrorCode> {
        let data = part.data;
        let result = {
            let mut guard = self.ctx.inner.lock();
            guard.digest_encrypt_update(self.handle, &data)
        }?;
        Ok(result)
    }

    fn decrypt_digest_update(&mut self, part: Chunk) -> Result<Vec<u8>, ErrorCode> {
        let data = part.data;
        let result = {
            let mut guard = self.ctx.inner.lock();
            guard.decrypt_digest_update(self.handle, &data)
        }?;
        Ok(result)
    }

    fn sign_encrypt_update(&mut self, part: Chunk) -> Result<Vec<u8>, ErrorCode> {
        let data = part.data;
        let result = {
            let mut guard = self.ctx.inner.lock();
            guard.sign_encrypt_update(self.handle, &data)
        }?;
        Ok(result)
    }

    fn decrypt_verify_update(&mut self, part: Chunk) -> Result<Vec<u8>, ErrorCode> {
        let data = part.data;
        let result = {
            let mut guard = self.ctx.inner.lock();
            guard.decrypt_verify_update(self.handle, &data)
        }?;
        Ok(result)
    }

    fn encrypt_init(
        &mut self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
    ) -> Result<session_iface::Encryptor, ErrorCode> {
        let key_handle = key.get::<ObjectHost>().get_handle();
        {
            let mut guard = self.ctx.inner.lock();
            guard.encrypt_init(self.handle, &mechanism, key_handle)?;
        }
        Ok(crypto_iface::Encryptor::new(EncryptorHost::new(
            self.ctx.clone(),
            self.handle,
        )))
    }

    fn decrypt_init(
        &mut self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
    ) -> Result<session_iface::Decryptor, ErrorCode> {
        let key_handle = key.get::<ObjectHost>().get_handle();
        {
            let mut guard = self.ctx.inner.lock();
            guard.decrypt_init(self.handle, &mechanism, key_handle)?;
        }
        Ok(crypto_iface::Decryptor::new(DecryptorHost::new(
            self.ctx.clone(),
            self.handle,
        )))
    }

    fn sign_init(
        &mut self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
    ) -> Result<session_iface::Signer, ErrorCode> {
        let key_handle = key.get::<ObjectHost>().get_handle();
        {
            let mut guard = self.ctx.inner.lock();
            guard.sign_init(self.handle, &mechanism, key_handle)?;
        }
        Ok(crypto_iface::Signer::new(SignerHost::new(
            self.ctx.clone(),
            self.handle,
        )))
    }

    fn verify_init(
        &mut self,
        mechanism: Mechanism,
        key: object_iface::ObjectBorrow<'_>,
    ) -> Result<session_iface::Verifier, ErrorCode> {
        let key_handle = key.get::<ObjectHost>().get_handle();
        {
            let mut guard = self.ctx.inner.lock();
            guard.verify_init(self.handle, &mechanism, key_handle)?;
        }
        Ok(crypto_iface::Verifier::new(VerifierHost::new(
            self.ctx.clone(),
            self.handle,
        )))
    }

    fn digest_init(&mut self, mechanism: Mechanism) -> Result<session_iface::Digester, ErrorCode> {
        {
            let mut guard = self.ctx.inner.lock();
            guard.digest_init(self.handle, &mechanism)?;
        }
        Ok(crypto_iface::Digester::new(DigesterHost::new(
            self.ctx.clone(),
            self.handle,
        )))
    }

    fn digest_key(&mut self, key: object_iface::ObjectBorrow<'_>) -> Result<(), ErrorCode> {
        let key_handle = key.get::<ObjectHost>().get_handle();
        {
            let mut guard = self.ctx.inner.lock();
            guard.digest_key(self.handle, key_handle)
        }
    }

    fn generate_key(
        &mut self,
        mechanism: bindings::pkcs11::core::core::Mechanism,
        template: bindings::pkcs11::core::core::AttributeTemplate,
    ) -> Result<session_iface::Object, ErrorCode> {
        let handle = self.ctx.generate_key(self.handle, &mechanism, &template)?;
        Ok(session_iface::Object::new(ObjectHost::new(
            self.ctx.clone(),
            self.handle,
            handle,
        )))
    }

    fn generate_key_pair(
        &mut self,
        mechanism: bindings::pkcs11::core::core::Mechanism,
        public_template: bindings::pkcs11::core::core::AttributeTemplate,
        private_template: bindings::pkcs11::core::core::AttributeTemplate,
    ) -> Result<(session_iface::Object, session_iface::Object), ErrorCode> {
        let (public, private) = self.ctx.generate_key_pair(
            self.handle,
            &mechanism,
            &public_template,
            &private_template,
        )?;
        let public_obj =
            session_iface::Object::new(ObjectHost::new(self.ctx.clone(), self.handle, public));
        let private_obj =
            session_iface::Object::new(ObjectHost::new(self.ctx.clone(), self.handle, private));
        Ok((public_obj, private_obj))
    }

    fn derive_key(
        &mut self,
        base_key: object_iface::ObjectBorrow<'_>,
        mechanism: bindings::pkcs11::core::core::Mechanism,
        template: bindings::pkcs11::core::core::AttributeTemplate,
    ) -> Result<session_iface::Object, ErrorCode> {
        let base = base_key.get::<ObjectHost>().get_handle();
        let handle = self
            .ctx
            .derive_key(self.handle, base, &mechanism, &template)?;
        Ok(session_iface::Object::new(ObjectHost::new(
            self.ctx.clone(),
            self.handle,
            handle,
        )))
    }

    fn wrap_key(
        &mut self,
        mechanism: bindings::pkcs11::core::core::Mechanism,
        wrapping_key: object_iface::ObjectBorrow<'_>,
        key: object_iface::ObjectBorrow<'_>,
    ) -> Result<Vec<u8>, ErrorCode> {
        let wrapping_handle = wrapping_key.get::<ObjectHost>().get_handle();
        let target_handle = key.get::<ObjectHost>().get_handle();
        self.ctx
            .wrap_key(self.handle, &mechanism, wrapping_handle, target_handle)
    }

    fn unwrap_key(
        &mut self,
        mechanism: bindings::pkcs11::core::core::Mechanism,
        wrapping_key: object_iface::ObjectBorrow<'_>,
        wrapped_key: Vec<u8>,
        template: bindings::pkcs11::core::core::AttributeTemplate,
    ) -> Result<session_iface::Object, ErrorCode> {
        let wrapping_handle = wrapping_key.get::<ObjectHost>().get_handle();
        let handle = self.ctx.unwrap_key(
            self.handle,
            &mechanism,
            wrapping_handle,
            &wrapped_key,
            &template,
        )?;
        Ok(session_iface::Object::new(ObjectHost::new(
            self.ctx.clone(),
            self.handle,
            handle,
        )))
    }

    fn seed_random(&mut self, seed: Vec<u8>) -> Result<(), ErrorCode> {
        self.ctx.seed_random(self.handle, &seed)
    }

    fn generate_random(&mut self, len: u32) -> Result<Vec<u8>, ErrorCode> {
        self.ctx.generate_random(self.handle, len)
    }
}

/// Managed PKCS#11 object handle tied to a parent session.
struct ObjectInner {
    ctx: AdapterContext,
    session: u32,
    handle: u32,
}

impl ObjectInner {
    fn new(ctx: AdapterContext, session: u32, handle: u32) -> Self {
        Self {
            ctx,
            session,
            handle,
        }
    }

    fn handle_raw(&self) -> u32 {
        self.handle
    }

    fn get_size(&mut self) -> Result<u64, ErrorCode> {
        self.ctx
            .inner
            .lock()
            .get_object_size(self.session, self.handle)
    }

    fn get_attributes(&mut self, tags: &[u32]) -> Result<Vec<WitAttribute>, ErrorCode> {
        self.ctx.get_attributes(self.session, self.handle, tags)
    }

    fn set_attributes(&mut self, template: &AttributeTemplate) -> Result<(), ErrorCode> {
        self.ctx.set_attributes(self.session, self.handle, template)
    }

    fn destroy(&mut self) -> Result<(), ErrorCode> {
        if self.handle != 0 {
            self.ctx.destroy_object(self.session, self.handle)?;
            self.handle = 0;
        }
        Ok(())
    }
}

pub struct ObjectHost {
    inner: Mutex<ObjectInner>,
}

impl ObjectHost {
    fn new(ctx: AdapterContext, session: u32, handle: u32) -> Self {
        Self {
            inner: Mutex::new(ObjectInner::new(ctx, session, handle)),
        }
    }

    fn with_inner<R>(
        &self,
        f: impl FnOnce(&mut ObjectInner) -> Result<R, ErrorCode>,
    ) -> Result<R, ErrorCode> {
        let mut guard = self.inner.lock();
        f(&mut guard)
    }
}

impl object_iface::GuestObject for ObjectHost {
    fn get_handle(&self) -> u32 {
        self.inner.lock().handle_raw()
    }

    fn get_size(&self) -> Result<u64, ErrorCode> {
        self.with_inner(|inner| inner.get_size())
    }

    fn get_attributes(&self, tags: Vec<u32>) -> Result<Vec<WitAttribute>, ErrorCode> {
        self.with_inner(|inner| inner.get_attributes(&tags))
    }

    fn set_attributes(&self, template: AttributeTemplate) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.set_attributes(&template))
    }

    fn destroy(&self) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.destroy())
    }
}

/// Iterator over search results produced by C_FindObjects.
struct SearchInner {
    ctx: AdapterContext,
    session: u32,
    active: bool,
}

impl SearchInner {
    fn new(ctx: AdapterContext, session: u32) -> Self {
        Self {
            ctx,
            session,
            active: true,
        }
    }

    fn next(&mut self, max: u32) -> Result<Vec<u32>, ErrorCode> {
        self.ctx.find_objects(self.session, max)
    }

    fn finish(&mut self) -> Result<(), ErrorCode> {
        if self.active {
            self.ctx.find_objects_final(self.session)?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for SearchInner {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

pub struct SearchHost {
    inner: Mutex<SearchInner>,
}

impl SearchHost {
    fn new(ctx: AdapterContext, session: u32) -> Self {
        Self {
            inner: Mutex::new(SearchInner::new(ctx, session)),
        }
    }

    fn with_inner<R>(
        &self,
        f: impl FnOnce(&mut SearchInner) -> Result<R, ErrorCode>,
    ) -> Result<R, ErrorCode> {
        let mut guard = self.inner.lock();
        f(&mut guard)
    }
}

impl object_iface::GuestSearch for SearchHost {
    fn next(&self, max: u32) -> Result<Vec<u32>, ErrorCode> {
        self.with_inner(|inner| inner.next(max))
    }

    fn finish(&self) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.finish())
    }
}

struct EncryptorInner {
    ctx: AdapterContext,
    session: u32,
    active: bool,
}

impl EncryptorInner {
    fn new(ctx: AdapterContext, session: u32) -> Self {
        Self {
            ctx,
            session,
            active: true,
        }
    }
}

impl Drop for EncryptorInner {
    fn drop(&mut self) {
        if self.active {
            let _ = self.ctx.inner.lock().encrypt_abort(self.session);
        }
    }
}

impl EncryptorInner {
    fn update(&mut self, part: Chunk) -> Result<Vec<u8>, ErrorCode> {
        let data = part.data;
        let result = {
            let mut guard = self.ctx.inner.lock();
            guard.encrypt_update(self.session, &data)
        }?;
        Ok(result)
    }

    fn final_(&mut self, max_size: u32) -> Result<Vec<u8>, ErrorCode> {
        let result = {
            let mut guard = self.ctx.inner.lock();
            guard.encrypt_final(self.session, max_size)
        }?;
        self.active = false;
        Ok(result)
    }

    fn abort(&mut self) -> Result<(), ErrorCode> {
        {
            let mut guard = self.ctx.inner.lock();
            guard.encrypt_abort(self.session)
        }?;
        self.active = false;
        Ok(())
    }
}

pub struct EncryptorHost {
    inner: Mutex<EncryptorInner>,
}

impl EncryptorHost {
    fn new(ctx: AdapterContext, session: u32) -> Self {
        Self {
            inner: Mutex::new(EncryptorInner::new(ctx, session)),
        }
    }

    fn with_inner<R>(
        &self,
        f: impl FnOnce(&mut EncryptorInner) -> Result<R, ErrorCode>,
    ) -> Result<R, ErrorCode> {
        let mut guard = self.inner.lock();
        f(&mut guard)
    }
}

impl crypto_iface::GuestEncryptor for EncryptorHost {
    fn update(&self, part: Chunk) -> Result<Vec<u8>, ErrorCode> {
        self.with_inner(|inner| inner.update(part))
    }

    fn final_(&self, max_size: u32) -> Result<Vec<u8>, ErrorCode> {
        self.with_inner(|inner| inner.final_(max_size))
    }

    fn abort(&self) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.abort())
    }
}

struct DecryptorInner {
    ctx: AdapterContext,
    session: u32,
    active: bool,
}

impl DecryptorInner {
    fn new(ctx: AdapterContext, session: u32) -> Self {
        Self {
            ctx,
            session,
            active: true,
        }
    }
}

impl Drop for DecryptorInner {
    fn drop(&mut self) {
        if self.active {
            let _ = self.ctx.inner.lock().decrypt_abort(self.session);
        }
    }
}

impl DecryptorInner {
    fn update(&mut self, part: Chunk) -> Result<Vec<u8>, ErrorCode> {
        let data = part.data;
        let result = {
            let mut guard = self.ctx.inner.lock();
            guard.decrypt_update(self.session, &data)
        }?;
        Ok(result)
    }

    fn final_(&mut self, max_size: u32) -> Result<Vec<u8>, ErrorCode> {
        let result = {
            let mut guard = self.ctx.inner.lock();
            guard.decrypt_final(self.session, max_size)
        }?;
        self.active = false;
        Ok(result)
    }

    fn abort(&mut self) -> Result<(), ErrorCode> {
        {
            let mut guard = self.ctx.inner.lock();
            guard.decrypt_abort(self.session)
        }?;
        self.active = false;
        Ok(())
    }
}

pub struct DecryptorHost {
    inner: Mutex<DecryptorInner>,
}

impl DecryptorHost {
    fn new(ctx: AdapterContext, session: u32) -> Self {
        Self {
            inner: Mutex::new(DecryptorInner::new(ctx, session)),
        }
    }

    fn with_inner<R>(
        &self,
        f: impl FnOnce(&mut DecryptorInner) -> Result<R, ErrorCode>,
    ) -> Result<R, ErrorCode> {
        let mut guard = self.inner.lock();
        f(&mut guard)
    }
}

impl crypto_iface::GuestDecryptor for DecryptorHost {
    fn update(&self, part: Chunk) -> Result<Vec<u8>, ErrorCode> {
        self.with_inner(|inner| inner.update(part))
    }

    fn final_(&self, max_size: u32) -> Result<Vec<u8>, ErrorCode> {
        self.with_inner(|inner| inner.final_(max_size))
    }

    fn abort(&self) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.abort())
    }
}

struct SignerInner {
    ctx: AdapterContext,
    session: u32,
    active: bool,
}

impl SignerInner {
    fn new(ctx: AdapterContext, session: u32) -> Self {
        Self {
            ctx,
            session,
            active: true,
        }
    }
}

pub struct SignerHost {
    inner: Mutex<SignerInner>,
}

impl SignerHost {
    fn new(ctx: AdapterContext, session: u32) -> Self {
        Self {
            inner: Mutex::new(SignerInner::new(ctx, session)),
        }
    }

    fn with_inner<R>(
        &self,
        f: impl FnOnce(&mut SignerInner) -> Result<R, ErrorCode>,
    ) -> Result<R, ErrorCode> {
        let mut guard = self.inner.lock();
        f(&mut guard)
    }
}

impl crypto_iface::GuestSigner for SignerHost {
    fn update(&self, part: Chunk) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.update(part))
    }

    fn final_(&self) -> Result<Vec<u8>, ErrorCode> {
        self.with_inner(|inner| inner.final_())
    }

    fn abort(&self) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.abort())
    }
}

impl Drop for SignerInner {
    fn drop(&mut self) {
        if self.active {
            let _ = self.ctx.inner.lock().sign_abort(self.session);
        }
    }
}

impl SignerInner {
    fn update(&mut self, part: Chunk) -> Result<(), ErrorCode> {
        let data = part.data;
        {
            let mut guard = self.ctx.inner.lock();
            guard.sign_update(self.session, &data)
        }?;
        Ok(())
    }

    fn final_(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let signature = {
            let mut guard = self.ctx.inner.lock();
            guard.sign_final(self.session)
        }?;
        self.active = false;
        Ok(signature)
    }

    fn abort(&mut self) -> Result<(), ErrorCode> {
        {
            let mut guard = self.ctx.inner.lock();
            guard.sign_abort(self.session)
        }?;
        self.active = false;
        Ok(())
    }
}

struct VerifierInner {
    ctx: AdapterContext,
    session: u32,
    active: bool,
}

impl VerifierInner {
    fn new(ctx: AdapterContext, session: u32) -> Self {
        Self {
            ctx,
            session,
            active: true,
        }
    }
}

pub struct VerifierHost {
    inner: Mutex<VerifierInner>,
}

impl VerifierHost {
    fn new(ctx: AdapterContext, session: u32) -> Self {
        Self {
            inner: Mutex::new(VerifierInner::new(ctx, session)),
        }
    }

    fn with_inner<R>(
        &self,
        f: impl FnOnce(&mut VerifierInner) -> Result<R, ErrorCode>,
    ) -> Result<R, ErrorCode> {
        let mut guard = self.inner.lock();
        f(&mut guard)
    }
}

impl crypto_iface::GuestVerifier for VerifierHost {
    fn update(&self, part: Chunk) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.update(part))
    }

    fn final_(&self, signature: Vec<u8>) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.final_(signature))
    }

    fn abort(&self) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.abort())
    }
}

impl Drop for VerifierInner {
    fn drop(&mut self) {
        if self.active {
            let _ = self.ctx.inner.lock().verify_abort(self.session);
        }
    }
}

impl VerifierInner {
    fn update(&mut self, part: Chunk) -> Result<(), ErrorCode> {
        let data = part.data;
        {
            let mut guard = self.ctx.inner.lock();
            guard.verify_update(self.session, &data)
        }?;
        Ok(())
    }

    fn final_(&mut self, signature: Vec<u8>) -> Result<(), ErrorCode> {
        {
            let mut guard = self.ctx.inner.lock();
            guard.verify_final(self.session, &signature)
        }?;
        self.active = false;
        Ok(())
    }

    fn abort(&mut self) -> Result<(), ErrorCode> {
        {
            let mut guard = self.ctx.inner.lock();
            guard.verify_abort(self.session)
        }?;
        self.active = false;
        Ok(())
    }
}

struct DigesterInner {
    ctx: AdapterContext,
    session: u32,
    active: bool,
}

impl DigesterInner {
    fn new(ctx: AdapterContext, session: u32) -> Self {
        Self {
            ctx,
            session,
            active: true,
        }
    }
}

impl Drop for DigesterInner {
    fn drop(&mut self) {
        if self.active {
            let _ = self.ctx.inner.lock().digest_abort(self.session);
        }
    }
}

impl DigesterInner {
    fn update(&mut self, part: Chunk) -> Result<(), ErrorCode> {
        let data = part.data;
        {
            let mut guard = self.ctx.inner.lock();
            guard.digest_update(self.session, &data)
        }?;
        Ok(())
    }

    fn final_(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let digest = {
            let mut guard = self.ctx.inner.lock();
            guard.digest_final(self.session)
        }?;
        self.active = false;
        Ok(digest)
    }

    fn abort(&mut self) -> Result<(), ErrorCode> {
        {
            let mut guard = self.ctx.inner.lock();
            guard.digest_abort(self.session)
        }?;
        self.active = false;
        Ok(())
    }
}

pub struct DigesterHost {
    inner: Mutex<DigesterInner>,
}

impl DigesterHost {
    fn new(ctx: AdapterContext, session: u32) -> Self {
        Self {
            inner: Mutex::new(DigesterInner::new(ctx, session)),
        }
    }

    fn with_inner<R>(
        &self,
        f: impl FnOnce(&mut DigesterInner) -> Result<R, ErrorCode>,
    ) -> Result<R, ErrorCode> {
        let mut guard = self.inner.lock();
        f(&mut guard)
    }
}

impl crypto_iface::GuestDigester for DigesterHost {
    fn update(&self, part: Chunk) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.update(part))
    }

    fn final_(&self) -> Result<Vec<u8>, ErrorCode> {
        self.with_inner(|inner| inner.final_())
    }

    fn abort(&self) -> Result<(), ErrorCode> {
        self.with_inner(|inner| inner.abort())
    }
}

impl object_iface::Guest for Pkcs11Component {
    type Object = ObjectHost;
    type Search = SearchHost;
}

impl crypto_iface::Guest for Pkcs11Component {
    type Encryptor = EncryptorHost;
    type Decryptor = DecryptorHost;
    type Signer = SignerHost;
    type Verifier = VerifierHost;
    type Digester = DigesterHost;
}

/// Slot manager implementation bridging WIT calls to native PKCS#11.
impl Pkcs11Component {
    fn ctx() -> AdapterContext {
        adapter()
    }

    fn env_config() -> Option<String> {
        let loader = FilesystemLoader::default();
        env::var("SOFTHSM_LIB")
            .or_else(|_| env::var("PKCS11_MODULE_PATH"))
            .ok()
            .and_then(|path| loader.parse(&path).ok())
            .map(|cfg| cfg.raw)
    }
}

impl slot_manager::Guest for Pkcs11Component {
    fn get_info() -> Result<ModuleInfo, ErrorCode> {
        Self::ctx().module_info()
    }

    fn initialize(config: Option<String>) -> Result<(), ErrorCode> {
        let ctx = Self::ctx();
        let incoming = config
            .map(|raw| raw.trim().to_string())
            .filter(|raw| !raw.is_empty());
        let spec = incoming
            .or_else(|| ctx.current_config())
            .or_else(|| Self::env_config())
            .ok_or(ErrorCode::ArgumentsBad)?;
        ctx.ensure_initialized(&spec)
    }

    fn finalize() -> Result<(), ErrorCode> {
        Self::ctx().finalize()
    }

    fn init_token(slot: u32, so_pin: Option<String>, label: String) -> Result<(), ErrorCode> {
        Self::ctx().init_token(slot, so_pin, label)
    }

    fn get_slot_list(token_present: bool) -> Result<Vec<u32>, ErrorCode> {
        Self::ctx().slot_list(token_present)
    }

    fn get_slot_info(slot: u32) -> Result<SlotInfo, ErrorCode> {
        Self::ctx().slot_info(slot)
    }

    fn get_token_info(slot: u32) -> Result<TokenInfo, ErrorCode> {
        Self::ctx().token_info(slot)
    }

    fn wait_for_slot_event(
        flags: slot_manager::WaitFlags,
    ) -> Result<slot_manager::SlotEvent, ErrorCode> {
        Self::ctx().wait_for_slot_event(flags)
    }

    fn close_all_sessions(slot: u32) -> Result<(), ErrorCode> {
        Self::ctx().close_all_sessions(slot)
    }

    fn get_mechanism_list(slot: u32) -> Result<Vec<MechanismType>, ErrorCode> {
        Self::ctx().mechanism_list(slot)
    }

    fn get_mechanism_info(slot: u32, mechanism: MechanismType) -> Result<MechanismInfo, ErrorCode> {
        Self::ctx().mechanism_info(slot, mechanism)
    }

    fn open_session(
        slot: u32,
        flags: WitSessionFlags,
    ) -> Result<session_iface::Session, ErrorCode> {
        let ctx = Self::ctx();
        let handle = ctx.open_session(slot, flags)?;
        Ok(session_iface::Session::new(SessionHost::new(ctx, handle)))
    }
}

#[allow(non_camel_case_types)]
mod ffi {
    use std::ffi::c_void;

    pub type CK_RV = u64;
    pub const CKR_OK: CK_RV = 0;
    pub const CKR_GENERAL_ERROR: CK_RV = 0x0000_0005;
    pub const CKR_ARGUMENTS_BAD: CK_RV = 0x0000_0007;
    pub const CKR_NO_EVENT: CK_RV = 0x0000_0008;
    pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x0000_0054;
    pub const CKR_BUFFER_TOO_SMALL: CK_RV = 0x0000_0150;

    pub type CK_ULONG = u64;
    pub type CK_SLOT_ID = u64;
    pub type CK_BBOOL = u8;
    pub type CK_FLAGS = u64;
    pub type CK_UTF8CHAR = u8;
    pub type CK_MECHANISM_TYPE = u64;
    pub type CK_SESSION_HANDLE = u64;
    pub type CK_USER_TYPE = u64;
    pub type CK_STATE = u64;
    pub type CK_BYTE = u8;
    pub type CK_OBJECT_HANDLE = u64;
    pub type CK_ATTRIBUTE_TYPE = u64;
    pub const CK_INVALID_HANDLE: CK_OBJECT_HANDLE = 0;
    pub type CK_CREATEMUTEX = Option<unsafe extern "C" fn(*mut *mut c_void) -> CK_RV>;
    pub type CK_DESTROYMUTEX = Option<unsafe extern "C" fn(*mut c_void) -> CK_RV>;
    pub type CK_LOCKMUTEX = Option<unsafe extern "C" fn(*mut c_void) -> CK_RV>;
    pub type CK_UNLOCKMUTEX = Option<unsafe extern "C" fn(*mut c_void) -> CK_RV>;

    pub const TOKEN_LABEL_LEN: usize = 32;
    pub const CK_UNAVAILABLE_INFORMATION: CK_ULONG = !0;

    pub const CKU_SO: CK_USER_TYPE = 0;
    pub const CKU_USER: CK_USER_TYPE = 1;
    pub const CKU_CONTEXT_SPECIFIC: CK_USER_TYPE = 2;

    pub const CKF_TOKEN_PRESENT: CK_FLAGS = 0x0000_0001;
    pub const CKF_REMOVABLE_DEVICE: CK_FLAGS = 0x0000_0002;
    pub const CKF_HW_SLOT: CK_FLAGS = 0x0000_0004;

    pub const CKF_RNG: CK_FLAGS = 0x0000_0001;
    pub const CKF_WRITE_PROTECTED: CK_FLAGS = 0x0000_0002;
    pub const CKF_LOGIN_REQUIRED: CK_FLAGS = 0x0000_0004;
    pub const CKF_USER_PIN_INITIALIZED: CK_FLAGS = 0x0000_0008;
    pub const CKF_RESTORE_KEY_NOT_NEEDED: CK_FLAGS = 0x0000_0020;
    pub const CKF_CLOCK_ON_TOKEN: CK_FLAGS = 0x0000_0040;
    pub const CKF_PROTECTED_AUTHENTICATION_PATH: CK_FLAGS = 0x0000_0100;
    pub const CKF_DUAL_CRYPTO_OPERATIONS: CK_FLAGS = 0x0000_0200;
    pub const CKF_TOKEN_INITIALIZED: CK_FLAGS = 0x0000_0400;
    pub const CKF_SECONDARY_AUTHENTICATION: CK_FLAGS = 0x0000_0800;
    pub const CKF_USER_PIN_COUNT_LOW: CK_FLAGS = 0x0000_1000;
    pub const CKF_USER_PIN_FINAL_TRY: CK_FLAGS = 0x0000_2000;
    pub const CKF_USER_PIN_LOCKED: CK_FLAGS = 0x0000_4000;
    pub const CKF_USER_PIN_TO_BE_CHANGED: CK_FLAGS = 0x0000_8000;
    pub const CKF_SO_PIN_COUNT_LOW: CK_FLAGS = 0x0001_0000;
    pub const CKF_SO_PIN_FINAL_TRY: CK_FLAGS = 0x0002_0000;
    pub const CKF_SO_PIN_LOCKED: CK_FLAGS = 0x0004_0000;
    pub const CKF_SO_PIN_TO_BE_CHANGED: CK_FLAGS = 0x0008_0000;
    pub const CKF_ERROR_STATE: CK_FLAGS = 0x0100_0000;

    pub const CKF_RW_SESSION: CK_FLAGS = 0x0000_0002;
    pub const CKF_SERIAL_SESSION: CK_FLAGS = 0x0000_0004;

    pub const CKF_HW: CK_FLAGS = 0x0000_0001;
    pub const CKF_ENCRYPT: CK_FLAGS = 0x0000_0002;
    pub const CKF_DECRYPT: CK_FLAGS = 0x0000_0004;
    pub const CKF_DIGEST: CK_FLAGS = 0x0000_0008;
    pub const CKF_SIGN: CK_FLAGS = 0x0000_0010;
    pub const CKF_SIGN_RECOVER: CK_FLAGS = 0x0000_0020;
    pub const CKF_VERIFY: CK_FLAGS = 0x0000_0040;
    pub const CKF_VERIFY_RECOVER: CK_FLAGS = 0x0000_0080;
    pub const CKF_GENERATE: CK_FLAGS = 0x0000_0100;
    pub const CKF_GENERATE_KEY_PAIR: CK_FLAGS = 0x0000_0200;
    pub const CKF_WRAP: CK_FLAGS = 0x0000_0400;
    pub const CKF_UNWRAP: CK_FLAGS = 0x0000_0800;
    pub const CKF_DERIVE: CK_FLAGS = 0x0000_1000;
    pub const CKF_EXTENSION: CK_FLAGS = 0x8000_0000;
    pub const CKF_OS_LOCKING_OK: CK_FLAGS = 0x0000_0002;
    pub const CKF_DONT_BLOCK: CK_FLAGS = 0x0000_0001;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct CK_VERSION {
        pub major: u8,
        pub minor: u8,
    }

    impl Default for CK_VERSION {
        fn default() -> Self {
            Self { major: 0, minor: 0 }
        }
    }

    #[repr(C)]
    pub struct CK_INFO {
        pub cryptoki_version: CK_VERSION,
        pub manufacturer_id: [CK_UTF8CHAR; 32],
        pub flags: CK_FLAGS,
        pub library_description: [CK_UTF8CHAR; 32],
        pub library_version: CK_VERSION,
    }

    impl Default for CK_INFO {
        fn default() -> Self {
            Self {
                cryptoki_version: CK_VERSION::default(),
                manufacturer_id: [0; 32],
                flags: 0,
                library_description: [0; 32],
                library_version: CK_VERSION::default(),
            }
        }
    }

    #[repr(C)]
    pub struct CK_SLOT_INFO {
        pub slot_description: [CK_UTF8CHAR; 64],
        pub manufacturer_id: [CK_UTF8CHAR; 32],
        pub flags: CK_FLAGS,
        pub hardware_version: CK_VERSION,
        pub firmware_version: CK_VERSION,
    }

    impl Default for CK_SLOT_INFO {
        fn default() -> Self {
            Self {
                slot_description: [0; 64],
                manufacturer_id: [0; 32],
                flags: 0,
                hardware_version: CK_VERSION::default(),
                firmware_version: CK_VERSION::default(),
            }
        }
    }

    #[repr(C)]
    pub struct CK_TOKEN_INFO {
        pub label: [CK_UTF8CHAR; 32],
        pub manufacturer_id: [CK_UTF8CHAR; 32],
        pub model: [CK_UTF8CHAR; 16],
        pub serial_number: [CK_UTF8CHAR; 16],
        pub flags: CK_FLAGS,
        pub max_session_count: CK_ULONG,
        pub session_count: CK_ULONG,
        pub max_rw_session_count: CK_ULONG,
        pub rw_session_count: CK_ULONG,
        pub max_pin_len: CK_ULONG,
        pub min_pin_len: CK_ULONG,
        pub total_public_memory: CK_ULONG,
        pub free_public_memory: CK_ULONG,
        pub total_private_memory: CK_ULONG,
        pub free_private_memory: CK_ULONG,
        pub hardware_version: CK_VERSION,
        pub firmware_version: CK_VERSION,
        pub utc_time: [CK_UTF8CHAR; 16],
    }

    impl Default for CK_TOKEN_INFO {
        fn default() -> Self {
            Self {
                label: [0; 32],
                manufacturer_id: [0; 32],
                model: [0; 16],
                serial_number: [0; 16],
                flags: 0,
                max_session_count: 0,
                session_count: 0,
                max_rw_session_count: 0,
                rw_session_count: 0,
                max_pin_len: 0,
                min_pin_len: 0,
                total_public_memory: CK_UNAVAILABLE_INFORMATION,
                free_public_memory: CK_UNAVAILABLE_INFORMATION,
                total_private_memory: CK_UNAVAILABLE_INFORMATION,
                free_private_memory: CK_UNAVAILABLE_INFORMATION,
                hardware_version: CK_VERSION::default(),
                firmware_version: CK_VERSION::default(),
                utc_time: [0; 16],
            }
        }
    }

    #[repr(C)]
    pub struct CK_MECHANISM_INFO {
        pub min_key_size: CK_ULONG,
        pub max_key_size: CK_ULONG,
        pub flags: CK_FLAGS,
    }

    impl Default for CK_MECHANISM_INFO {
        fn default() -> Self {
            Self {
                min_key_size: 0,
                max_key_size: 0,
                flags: 0,
            }
        }
    }

    #[repr(C)]
    pub struct CK_MECHANISM {
        pub mechanism: CK_MECHANISM_TYPE,
        pub p_parameter: *mut c_void,
        pub ul_parameter_len: CK_ULONG,
    }

    pub const CKS_RO_PUBLIC_SESSION: CK_STATE = 0;
    pub const CKS_RO_USER_FUNCTIONS: CK_STATE = 1;
    pub const CKS_RW_PUBLIC_SESSION: CK_STATE = 2;
    pub const CKS_RW_USER_FUNCTIONS: CK_STATE = 3;
    pub const CKS_RW_SO_FUNCTIONS: CK_STATE = 4;

    #[repr(C)]
    pub struct CK_SESSION_INFO {
        pub slot_id: CK_SLOT_ID,
        pub state: CK_STATE,
        pub flags: CK_FLAGS,
        pub device_error: CK_ULONG,
    }

    impl Default for CK_SESSION_INFO {
        fn default() -> Self {
            Self {
                slot_id: 0,
                state: CKS_RO_PUBLIC_SESSION,
                flags: 0,
                device_error: 0,
            }
        }
    }

    #[repr(C)]
    pub struct CK_ATTRIBUTE {
        pub type_: CK_ATTRIBUTE_TYPE,
        pub p_value: *mut c_void,
        pub ul_value_len: CK_ULONG,
    }

    #[repr(C)]
    pub struct CK_C_INITIALIZE_ARGS {
        pub create_mutex: CK_CREATEMUTEX,
        pub destroy_mutex: CK_DESTROYMUTEX,
        pub lock_mutex: CK_LOCKMUTEX,
        pub unlock_mutex: CK_UNLOCKMUTEX,
        pub flags: CK_FLAGS,
        pub p_reserved: *mut c_void,
    }

    impl Default for CK_C_INITIALIZE_ARGS {
        fn default() -> Self {
            Self {
                create_mutex: None,
                destroy_mutex: None,
                lock_mutex: None,
                unlock_mutex: None,
                flags: 0,
                p_reserved: std::ptr::null_mut(),
            }
        }
    }
}

fn rv_to_error(rv: ffi::CK_RV) -> ErrorCode {
    match rv {
        ffi::CKR_OK => ErrorCode::Ok,
        ffi::CKR_GENERAL_ERROR => ErrorCode::GeneralError,
        ffi::CKR_ARGUMENTS_BAD => ErrorCode::ArgumentsBad,
        ffi::CKR_NO_EVENT => ErrorCode::NoEvent,
        ffi::CKR_FUNCTION_NOT_SUPPORTED => ErrorCode::FunctionNotSupported,
        0x0000_000A => ErrorCode::SlotIdInvalid,
        0x0000_000B => ErrorCode::TokenNotPresent,
        0x0000_000E => ErrorCode::TokenWriteProtected,
        0x0000_0019 => ErrorCode::SessionCount,
        0x0000_0020 => ErrorCode::SessionHandleInvalid,
        0x0000_0030 => ErrorCode::MechanismInvalid,
        0x0000_0031 => ErrorCode::MechanismParamInvalid,
        0x0000_0150 => ErrorCode::BufferTooSmall,
        other => ErrorCode::Unknown(other as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::exports::pkcs11::token::slot_manager;
    use crate::bindings::exports::pkcs11::token::slot_manager::Guest as _;
    use crate::{
        bindings::exports::pkcs11::crypto::crypto::GuestDigester, ObjectHost, SessionHost,
    };
    use std::{
        env,
        error::Error,
        path::Path,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn module_path() -> Option<String> {
        env::var("SOFTHSM_LIB")
            .or_else(|_| env::var("PKCS11_MODULE_PATH"))
            .ok()
    }

    fn config_string(module: &str) -> String {
        format!("module={module},mutex=os")
    }

    fn map_code<T>(context: &str, result: Result<T, ErrorCode>) -> Result<T, Box<dyn Error>> {
        result.map_err(|code| format!("{context}: {:?}", code).into())
    }

    #[test]
    fn pkcs11_integration_smoke() -> Result<(), Box<dyn Error>> {
        let module = match module_path() {
            Some(path) => path,
            None => {
                eprintln!(
                    "Skipping pkcs11_integration_smoke: set SOFTHSM_LIB or PKCS11_MODULE_PATH"
                );
                return Ok(());
            }
        };

        if !Path::new(&module).exists() {
            eprintln!(
                "Skipping pkcs11_integration_smoke: module path {module} does not exist on this host"
            );
            return Ok(());
        }

        map_code(
            "initialize",
            Pkcs11Component::initialize(Some(config_string(&module))),
        )?;

        let test_result: Result<(), Box<dyn Error>> = (|| {
            let slots = map_code("get_slot_list", Pkcs11Component::get_slot_list(false))?;
            if slots.is_empty() {
                eprintln!("Skipping pkcs11_integration_smoke: no slots reported by module");
                return Ok(());
            }

            let slot = slots[0];

            map_code("get_slot_info", Pkcs11Component::get_slot_info(slot))?;
            map_code("get_token_info", Pkcs11Component::get_token_info(slot))?;
            let mechanisms = map_code(
                "get_mechanism_list",
                Pkcs11Component::get_mechanism_list(slot),
            )?;
            if let Some(mech) = mechanisms.first() {
                map_code(
                    "get_mechanism_info",
                    Pkcs11Component::get_mechanism_info(slot, *mech),
                )?;
            }

            let session_flags = WitSessionFlags::SERIAL_SESSION | WitSessionFlags::RW_SESSION;
            let session = map_code(
                "open_session",
                Pkcs11Component::open_session(slot, session_flags),
            )?;
            let session_host = session.get::<SessionHost>();

            let info = map_code(
                "session.get_info",
                session_host.with_inner(|inner| inner.get_info()),
            )?;
            assert_eq!(info.slot, slot, "session info returns the expected slot");

            let random = map_code(
                "session.generate_random",
                session_host.with_inner(|inner| inner.generate_random(16)),
            )?;
            assert_eq!(
                random.len(),
                16,
                "module returned the requested random bytes"
            );

            let logged_in = if let Ok(pin) = env::var("PKCS11_USER_PIN") {
                let pin_bytes = pin.into_bytes();
                map_code(
                    "session.login",
                    session_host.with_inner(|inner| {
                        inner.login(UserType::User, WitCredential::Inline(pin_bytes.clone()))
                    }),
                )?;
                true
            } else {
                false
            };

            if logged_in {
                let test_data = b"wasm-pkcs11-integration".to_vec();
                let label = format!(
                    "wasm-test-{}",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                );
                let template: AttributeTemplate = vec![
                    WitAttribute {
                        tag: CKA_CLASS,
                        value: attribute_value_from_payload(AttributePayload::Uint32(CKO_DATA)),
                    },
                    WitAttribute {
                        tag: CKA_TOKEN,
                        value: attribute_value_from_payload(AttributePayload::Boolean(false)),
                    },
                    WitAttribute {
                        tag: CKA_LABEL,
                        value: attribute_value_from_payload(AttributePayload::ByteString(
                            label.clone().into_bytes(),
                        )),
                    },
                    WitAttribute {
                        tag: CKA_VALUE,
                        value: attribute_value_from_payload(AttributePayload::ByteString(
                            test_data.clone(),
                        )),
                    },
                ];

                let object = map_code(
                    "session.create_object",
                    session_host.with_inner(|inner| inner.create_object(template.clone())),
                )?;
                let object_host = object.get::<ObjectHost>();
                let size = map_code(
                    "object.get_size",
                    object_host.with_inner(|inner| inner.get_size()),
                )?;
                assert_eq!(size, test_data.len() as u64);

                map_code(
                    "object.destroy",
                    object_host.with_inner(|inner| inner.destroy()),
                )?;

                let rsa_id = vec![0xA5, 0x5A];
                let key_label = format!("{label}-rsa");
                let rsa_keygen = Mechanism {
                    kind: CKM_RSA_PKCS_KEY_PAIR_GEN,
                    parameter: None,
                };
                let (public_key, private_key) = map_code(
                    "session.generate_key_pair",
                    session_host.with_inner(|inner| {
                        inner.generate_key_pair(
                            rsa_keygen.clone(),
                            rsa_public_template(&key_label, &rsa_id),
                            rsa_private_template(&key_label, &rsa_id),
                        )
                    }),
                )?;
                let public_host = public_key.get::<ObjectHost>();
                let private_host = private_key.get::<ObjectHost>();

                let rsa_mechanism = Mechanism {
                    kind: CKM_RSA_PKCS,
                    parameter: None,
                };
                let recover_payload = b"rsa-recover-payload".to_vec();
                let recovered = map_code(
                    "session.sign_recover",
                    session_host.with_inner(|inner| {
                        inner.ctx.sign_recover(
                            inner.handle,
                            &rsa_mechanism,
                            private_host.get_handle(),
                            &recover_payload,
                            4096,
                        )
                    }),
                )?;
                assert!(
                    !recovered.truncated,
                    "sign_recover should not truncate recoverable data"
                );
                assert_eq!(
                    recovered.data, recover_payload,
                    "sign_recover returned original payload"
                );

                let verified = map_code(
                    "session.verify_recover",
                    session_host.with_inner(|inner| {
                        inner.ctx.verify_recover(
                            inner.handle,
                            &rsa_mechanism,
                            public_host.get_handle(),
                            &recovered.data,
                            4096,
                        )
                    }),
                )?;
                assert!(
                    !verified.truncated,
                    "verify_recover should not truncate recoverable data"
                );
                assert_eq!(
                    verified.data, recover_payload,
                    "verify_recover returned original payload"
                );

                let digest_mechanism = Mechanism {
                    kind: CKM_SHA256,
                    parameter: None,
                };
                let digester = map_code(
                    "session.digest_init",
                    session_host.with_inner(|inner| inner.digest_init(digest_mechanism.clone())),
                )?;
                let digester_host = digester.get::<DigesterHost>();
                map_code(
                    "session.digest_key",
                    session_host.with_inner(|inner| {
                        inner.ctx.digest_key(inner.handle, private_host.get_handle())
                    }),
                )?;
                let digest = map_code("digester.final", digester_host.final_())?;
                assert_eq!(
                    digest.len(),
                    32,
                    "SHA-256 digest over the private key should be 32 bytes"
                );

                map_code(
                    "public.destroy",
                    public_host.with_inner(|inner| inner.destroy()),
                )?;
                map_code(
                    "private.destroy",
                    private_host.with_inner(|inner| inner.destroy()),
                )?;

                map_code(
                    "session.logout",
                    session_host.with_inner(|inner| inner.logout()),
                )?;
            }

            if let Some(mech) = parse_mechanism_env("PKCS11_STATE_MECH") {
                exercise_state_serialization(&session_host, mech)?;
            }

            map_code(
                "session.close",
                session_host.with_inner(|inner| inner.close()),
            )?;
            drop(session);

            Ok(())
        })();

        let finalize_result = map_code("finalize", Pkcs11Component::finalize());

        match (test_result, finalize_result) {
            (Err(test_err), Err(finalize_err)) => {
                eprintln!("finalize after failure also failed: {finalize_err}");
                Err(test_err)
            }
            (Err(test_err), _) => Err(test_err),
            (_, Err(finalize_err)) => Err(finalize_err),
            (Ok(_), Ok(_)) => Ok(()),
        }
    }

    #[test]
    fn env_config_uses_canonical_form() {
        let original = env::var("PKCS11_MODULE_PATH").ok();
        env::set_var("PKCS11_MODULE_PATH", "/tmp/libpkcs11-test.so");
        env::remove_var("SOFTHSM_LIB");
        let config = Pkcs11Component::env_config().expect("env config to parse");
        assert_eq!(config, "module=/tmp/libpkcs11-test.so");
        match original {
            Some(val) => env::set_var("PKCS11_MODULE_PATH", val),
            None => env::remove_var("PKCS11_MODULE_PATH"),
        }
    }

    #[test]
    fn slot_filter_enforces_selected_slot() {
        let loader: Arc<dyn ModuleLoader> = Arc::new(FilesystemLoader::default());
        let mut native = NativePkcs11::new(loader);
        native.preferred_slot = Some(42);
        assert!(native.ensure_slot_allowed(42).is_ok());
        let err = native.ensure_slot_allowed(7).unwrap_err();
        assert!(matches!(err, ErrorCode::SlotIdInvalid));
    }

    #[test]
    fn wait_flags_to_ck_sets_dont_block() {
        let empty = slot_manager::WaitFlags::empty();
        assert_eq!(wait_flags_to_ck(empty), 0);
        let mut flags = slot_manager::WaitFlags::empty();
        flags |= slot_manager::WaitFlags::DONT_BLOCK;
        assert_eq!(wait_flags_to_ck(flags), ffi::CKF_DONT_BLOCK);
    }

    fn rsa_public_template(label: &str, id: &[u8]) -> AttributeTemplate {
        vec![
            WitAttribute {
                tag: CKA_CLASS,
                value: attribute_value_from_payload(AttributePayload::Uint32(CKO_PUBLIC_KEY)),
            },
            WitAttribute {
                tag: CKA_TOKEN,
                value: attribute_value_from_payload(AttributePayload::Boolean(false)),
            },
            WitAttribute {
                tag: CKA_LABEL,
                value: attribute_value_from_payload(AttributePayload::ByteString(
                    label.as_bytes().to_vec(),
                )),
            },
            WitAttribute {
                tag: CKA_ID,
                value: attribute_value_from_payload(AttributePayload::ByteString(id.to_vec())),
            },
            WitAttribute {
                tag: CKA_KEY_TYPE,
                value: attribute_value_from_payload(AttributePayload::Uint32(CKK_RSA)),
            },
            WitAttribute {
                tag: CKA_MODULUS_BITS,
                value: attribute_value_from_payload(AttributePayload::Uint32(2048)),
            },
            WitAttribute {
                tag: CKA_PUBLIC_EXPONENT,
                value: attribute_value_from_payload(AttributePayload::ByteString(vec![1, 0, 1])),
            },
            WitAttribute {
                tag: CKA_VERIFY,
                value: attribute_value_from_payload(AttributePayload::Boolean(true)),
            },
            WitAttribute {
                tag: CKA_VERIFY_RECOVER,
                value: attribute_value_from_payload(AttributePayload::Boolean(true)),
            },
        ]
    }

    fn rsa_private_template(label: &str, id: &[u8]) -> AttributeTemplate {
        vec![
            WitAttribute {
                tag: CKA_CLASS,
                value: attribute_value_from_payload(AttributePayload::Uint32(CKO_PRIVATE_KEY)),
            },
            WitAttribute {
                tag: CKA_TOKEN,
                value: attribute_value_from_payload(AttributePayload::Boolean(false)),
            },
            WitAttribute {
                tag: CKA_LABEL,
                value: attribute_value_from_payload(AttributePayload::ByteString(
                    label.as_bytes().to_vec(),
                )),
            },
            WitAttribute {
                tag: CKA_ID,
                value: attribute_value_from_payload(AttributePayload::ByteString(id.to_vec())),
            },
            WitAttribute {
                tag: CKA_KEY_TYPE,
                value: attribute_value_from_payload(AttributePayload::Uint32(CKK_RSA)),
            },
            WitAttribute {
                tag: CKA_PRIVATE,
                value: attribute_value_from_payload(AttributePayload::Boolean(true)),
            },
            WitAttribute {
                tag: CKA_SENSITIVE,
                value: attribute_value_from_payload(AttributePayload::Boolean(false)),
            },
            WitAttribute {
                tag: CKA_EXTRACTABLE,
                value: attribute_value_from_payload(AttributePayload::Boolean(true)),
            },
            WitAttribute {
                tag: CKA_SIGN,
                value: attribute_value_from_payload(AttributePayload::Boolean(true)),
            },
            WitAttribute {
                tag: CKA_SIGN_RECOVER,
                value: attribute_value_from_payload(AttributePayload::Boolean(true)),
            },
        ]
    }

    fn parse_mechanism_env(name: &str) -> Option<u64> {
        let raw = env::var(name).ok()?;
        if let Some(rest) = raw.strip_prefix("0x") {
            u64::from_str_radix(rest, 16).ok()
        } else if let Some(rest) = raw.strip_prefix("0X") {
            u64::from_str_radix(rest, 16).ok()
        } else {
            raw.parse().ok()
        }
    }

    fn exercise_state_serialization(
        session_host: &SessionHost,
        mechanism_kind: u64,
    ) -> Result<(), String> {
        let mechanism = Mechanism {
            kind: mechanism_kind,
            parameter: None,
        };
        let expected = {
            let digester = session_host
                .with_inner(|inner| inner.digest(mechanism.clone(), b"state-test-data".to_vec()))
                .map_err(|e| format!("baseline digest failed: {:?}", e))?;
            digester
        };

        let digester = session_host
            .with_inner(|inner| inner.digest_init(mechanism.clone()))
            .map_err(|e| format!("digest_init failed: {:?}", e))?;
        let digester_host = digester.get::<DigesterHost>();
        let chunk = Chunk {
            data: b"state-test-data".to_vec(),
            final_: false,
        };
        digester_host
            .update(chunk)
            .map_err(|e| format!("digest update failed: {:?}", e))?;

        match session_host.with_inner(|inner| inner.get_operation_state(4096)) {
            Ok(state) => {
                session_host
                    .with_inner(|inner| inner.set_operation_state(state.data.clone(), None, None))
                    .map_err(|e| format!("set operation state failed: {:?}", e))?;
                let mut chunk = Chunk {
                    data: Vec::new(),
                    final_: true,
                };
                chunk.data.extend_from_slice(b"");
                digester_host
                    .update(chunk.clone())
                    .map_err(|e| format!("digest update final failed: {:?}", e))?;
                let final_digest = digester_host
                    .final_()
                    .map_err(|e| format!("digest final failed: {:?}", e))?;
                if final_digest != expected {
                    return Err("operation state round trip mismatch".to_string());
                }
                Ok(())
            }
            Err(err) => Err(format!("get operation state not supported: {:?}", err)),
        }
    }
}

bindings::exports::pkcs11::crypto::crypto::__export_pkcs11_crypto_crypto_cabi!(Pkcs11Component with_types_in bindings::exports::pkcs11::crypto::crypto);
bindings::exports::pkcs11::object::object::__export_pkcs11_object_object_cabi!(Pkcs11Component with_types_in bindings::exports::pkcs11::object::object);
bindings::exports::pkcs11::session::session::__export_pkcs11_session_session_cabi!(Pkcs11Component with_types_in bindings::exports::pkcs11::session::session);
bindings::exports::pkcs11::token::slot_manager::__export_pkcs11_token_slot_manager_cabi!(Pkcs11Component with_types_in bindings::exports::pkcs11::token::slot_manager);
bindings::exports::pkcs11::registry::provider_registry::__export_pkcs11_registry_provider_registry_cabi!(Pkcs11Component with_types_in bindings::exports::pkcs11::registry::provider_registry);
