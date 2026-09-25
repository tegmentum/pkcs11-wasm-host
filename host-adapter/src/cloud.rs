#![allow(dead_code)]

use std::sync::Arc;

use thiserror::Error;

/// Trait abstracting a cloud-hosted PKCS#11 provider.
/// Implementations translate CloudModuleClient calls into vendor-specific RPCs.
pub trait CloudModuleClient: Send + Sync {
    /// Attempt to load a module identified by the configuration payload.
    fn load(&self, config: &CloudModuleConfig) -> Result<(), CloudLoaderError>;

    /// Enumerate slots exposed by the remote provider.
    fn slot_list(&self, token_present: bool) -> Result<Vec<u32>, CloudLoaderError>;

    /// Fetch module metadata information for diagnostics.
    fn module_info(&self) -> Result<CloudModuleInfo, CloudLoaderError>;
}

/// Thin wrapper around a boxed trait object so consumers can swap adapters at runtime.
#[derive(Clone)]
pub struct CloudModuleLoader {
    client: Arc<dyn CloudModuleClient>,
}

impl CloudModuleLoader {
    pub fn new(client: Arc<dyn CloudModuleClient>) -> Self {
        Self { client }
    }

    pub fn load(&self, config: &CloudModuleConfig) -> Result<(), CloudLoaderError> {
        self.client.load(config)
    }

    pub fn slot_list(&self, token_present: bool) -> Result<Vec<u32>, CloudLoaderError> {
        self.client.slot_list(token_present)
    }

    pub fn module_info(&self) -> Result<CloudModuleInfo, CloudLoaderError> {
        self.client.module_info()
    }
}

#[derive(Debug, Clone, Default)]
pub struct CloudModuleConfig {
    pub provider: String,
    pub endpoint: String,
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CloudModuleInfo {
    pub vendor: String,
    pub description: String,
    pub module_version: (u8, u8),
}

#[derive(Debug, Error)]
pub enum CloudLoaderError {
    #[error("missing provider identifier in cloud config")]
    MissingProvider,
    #[error("failed to authenticate with cloud provider: {0}")]
    AuthenticationFailed(String),
    #[error("cloud provider request failed: {0}")]
    RequestFailed(String),
}

/// Mock client used for tests and local development. Returns canned data without network IO.
pub struct MockCloudClient {
    slots: Vec<u32>,
    info: CloudModuleInfo,
}

impl MockCloudClient {
    pub fn new(slots: Vec<u32>, info: CloudModuleInfo) -> Self {
        Self { slots, info }
    }
}

impl CloudModuleClient for MockCloudClient {
    fn load(&self, _config: &CloudModuleConfig) -> Result<(), CloudLoaderError> {
        Ok(())
    }

    fn slot_list(&self, _token_present: bool) -> Result<Vec<u32>, CloudLoaderError> {
        Ok(self.slots.clone())
    }

    fn module_info(&self) -> Result<CloudModuleInfo, CloudLoaderError> {
        Ok(self.info.clone())
    }
}
