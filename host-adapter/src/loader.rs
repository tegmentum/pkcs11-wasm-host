use std::env;
use std::path::{Path, PathBuf};

use libloading::Library;
use thiserror::Error;

/// Preference for how PKCS#11 mutex callbacks should be configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MutexPreference {
    /// Let the adapter decide (defaults to OS-level locking).
    #[default]
    Auto,
    /// Explicitly request the token's OS-level locking support.
    OsThreads,
    /// Application will serialize access; no OS locking flag is set.
    None,
}

/// Parsed module configuration derived from the slot-manager config string.
#[derive(Debug, Clone)]
pub struct ModuleConfig {
    pub raw: String,
    pub module_path: PathBuf,
    pub mutex_preference: MutexPreference,
    pub slot_filter: Option<u64>,
}

impl ModuleConfig {
    fn canonical_string(path: &Path, pref: MutexPreference, slot: Option<u64>) -> String {
        let mut parts = vec![format!("module={}", path.display())];
        if let Some(entry) = match pref {
            MutexPreference::Auto => None,
            MutexPreference::OsThreads => Some("mutex=os".to_string()),
            MutexPreference::None => Some("mutex=none".to_string()),
        } {
            parts.push(entry);
        }
        if let Some(slot_id) = slot {
            parts.push(format!("slot={slot_id}"));
        }
        parts.join(",")
    }
}

/// Loaded module handle that keeps the `libloading::Library` alive.
pub struct ModuleHandle {
    pub config: ModuleConfig,
    pub library: Library,
}

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("pkcs11 module path missing from config string")]
    MissingModule,
    #[error("invalid module path `{0}`")]
    InvalidModule(String),
    #[error("module path `{path}` lies outside allowed roots")]
    OutsideAllowedRoots { path: String },
    #[error("failed to load `{path}`: {source}")]
    LoadFailure {
        path: String,
        #[source]
        source: libloading::Error,
    },
}

pub trait ModuleLoader: Send + Sync {
    fn parse(&self, raw: &str) -> Result<ModuleConfig, LoaderError>;
    fn load(&self, config: &ModuleConfig) -> Result<ModuleHandle, LoaderError>;
}

pub struct FilesystemLoader {
    allowed_roots: Option<Vec<PathBuf>>,
}

impl Default for FilesystemLoader {
    fn default() -> Self {
        Self::new_with_roots(Self::roots_from_env())
    }
}

impl FilesystemLoader {
    pub fn new_with_roots<I, P>(roots: I) -> Self
    where
        I: Into<Option<Vec<P>>>,
        P: Into<PathBuf>,
    {
        let allowed_roots = roots.into().map(|paths| {
            paths
                .into_iter()
                .map(|p| canonicalize_path(&p.into()))
                .collect()
        });
        Self { allowed_roots }
    }

    fn roots_from_env() -> Option<Vec<PathBuf>> {
        let raw = env::var("PKCS11_MODULE_ROOTS").ok()?;
        let mut roots = Vec::new();
        for entry in raw.split(':') {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            let root = canonicalize_path(&to_absolute(&PathBuf::from(trimmed)));
            roots.push(root);
        }
        if roots.is_empty() {
            None
        } else {
            Some(roots)
        }
    }

    fn normalize_path(&self, path: &str) -> Result<PathBuf, LoaderError> {
        if path.trim().is_empty() {
            return Err(LoaderError::InvalidModule(path.to_string()));
        }

        let buf = to_absolute(&PathBuf::from(path));
        self.ensure_allowed(&buf)?;

        Ok(buf)
    }

    fn ensure_allowed(&self, path: &Path) -> Result<(), LoaderError> {
        if let Some(roots) = &self.allowed_roots {
            let canonical = canonicalize_path(path);
            let permitted = roots.iter().any(|root| canonical.starts_with(root));
            if !permitted {
                return Err(LoaderError::OutsideAllowedRoots {
                    path: canonical.display().to_string(),
                });
            }
        }
        Ok(())
    }

    fn parse_kv(token: &str) -> (&str, Option<&str>) {
        if let Some((k, v)) = token.split_once('=') {
            (k.trim(), Some(v.trim()))
        } else {
            (token.trim(), None)
        }
    }
}

impl ModuleLoader for FilesystemLoader {
    fn parse(&self, raw: &str) -> Result<ModuleConfig, LoaderError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(LoaderError::MissingModule);
        }

        let mut module_path: Option<PathBuf> = None;
        let mut mutex_preference = MutexPreference::default();
        let mut slot_filter: Option<u64> = None;

        for token in trimmed.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }

            let (key, value) = Self::parse_kv(token);
            match (key.to_lowercase().as_str(), value) {
                ("module", Some(val)) => module_path = Some(self.normalize_path(val)?),
                ("mutex", Some(val)) => {
                    mutex_preference = match val.to_lowercase().as_str() {
                        "os" | "platform" => MutexPreference::OsThreads,
                        "none" | "app" => MutexPreference::None,
                        _ => MutexPreference::Auto,
                    };
                }
                ("slot", Some(val)) => {
                    let parsed = val
                        .parse::<u64>()
                        .map_err(|_| LoaderError::InvalidModule(val.to_string()))?;
                    slot_filter = Some(parsed);
                }
                (_, None) if module_path.is_none() => {
                    module_path = Some(self.normalize_path(key)?);
                }
                _ => {}
            }
        }

        let module_path = module_path.ok_or(LoaderError::MissingModule)?;
        let raw = ModuleConfig::canonical_string(&module_path, mutex_preference, slot_filter);

        Ok(ModuleConfig {
            raw,
            module_path,
            mutex_preference,
            slot_filter,
        })
    }

    fn load(&self, config: &ModuleConfig) -> Result<ModuleHandle, LoaderError> {
        unsafe {
            Library::new(&config.module_path).map(|library| ModuleHandle {
                config: config.clone(),
                library,
            })
        }
        .map_err(|source| LoaderError::LoadFailure {
            path: config.module_path.display().to_string(),
            source,
        })
    }
}

fn to_absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(cwd) = env::current_dir() {
        cwd.join(path)
    } else {
        path.to_path_buf()
    }
}

fn canonicalize_path(path: &Path) -> PathBuf {
    match path.canonicalize() {
        Ok(resolved) => resolved,
        Err(_) => {
            if let Some(parent) = path.parent() {
                let base = parent
                    .canonicalize()
                    .unwrap_or_else(|_| parent.to_path_buf());
                if let Some(name) = path.file_name() {
                    base.join(name)
                } else {
                    base
                }
            } else {
                path.to_path_buf()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_with_explicit_module_key() {
        let loader = FilesystemLoader::default();
        let cfg = loader
            .parse("module=/tmp/libpkcs11.dylib")
            .expect("parse succeeds");
        assert_eq!(cfg.mutex_preference, MutexPreference::Auto);
        assert_eq!(cfg.raw, "module=/tmp/libpkcs11.dylib");
    }

    #[test]
    fn parse_without_key_defaults_to_module() {
        let loader = FilesystemLoader::default();
        let cfg = loader.parse("/opt/libpkcs11.so").expect("parse succeeds");
        assert!(cfg.raw.starts_with("module=/opt/libpkcs11.so"));
    }

    #[test]
    fn parse_mutex_preference() {
        let loader = FilesystemLoader::default();
        let cfg = loader
            .parse("module=/tmp/libpkcs11.so, mutex=os")
            .expect("parse succeeds");
        assert_eq!(cfg.mutex_preference, MutexPreference::OsThreads);
        assert_eq!(cfg.raw, "module=/tmp/libpkcs11.so,mutex=os");
    }

    #[test]
    fn parse_slot_filter() {
        let loader = FilesystemLoader::default();
        let cfg = loader
            .parse("module=/tmp/libpkcs11.so,slot=2")
            .expect("parse succeeds");
        assert_eq!(cfg.slot_filter, Some(2));
        assert!(cfg.raw.contains("slot=2"));
    }

    #[test]
    fn rejects_path_outside_roots() {
        let loader = FilesystemLoader::new_with_roots(Some(vec!["/tmp/pkcs11-roots"]));
        let err = loader.parse("module=/etc/softhsm/lib.so").unwrap_err();
        assert!(matches!(err, LoaderError::OutsideAllowedRoots { .. }));
    }

    #[test]
    fn allows_path_within_roots() {
        let base = env::temp_dir().join("pkcs11-roots");
        let _ = fs::create_dir_all(&base);
        let path = base.join("libtest.so");
        let loader = FilesystemLoader::new_with_roots(Some(vec![base.clone()]));
        let cfg = loader
            .parse(&format!("module={}", path.display()))
            .expect("path inside root");
        assert!(cfg.raw.contains(&base.display().to_string()));
    }
}
