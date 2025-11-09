# wasm-pkcs11

WebAssembly host adapter for PKCS#11 cryptographic token interface standard.

## Overview

This project provides a WebAssembly Component Model adapter that bridges WebAssembly guest modules to native PKCS#11 providers (hardware tokens, HSMs, software tokens like SoftHSM).

## Structure

- `host-adapter/` - Rust implementation that wraps native PKCS#11 libraries
- `guest-smoke/` - Example WebAssembly guest component for testing
- `docs/` - Design documentation and implementation notes
- `wit/` - WIT interface definitions (git submodule)

## WIT Definitions

The WIT interface definitions are maintained in a separate repository: [pkcs11-wit](https://github.com/your-org/pkcs11-wit)

### Setup

After cloning this repository, initialize the WIT submodule:

```bash
git submodule update --init --recursive
```

**For local development before pushing pkcs11-wit to remote:**

If you haven't pushed pkcs11-wit to a remote repository yet, create a symlink:

```bash
ln -s ~/git/pkcs11-wit wit
```

Once pkcs11-wit is pushed to a remote repository, add it as a proper submodule:

```bash
rm wit  # Remove symlink
git submodule add https://github.com/your-org/pkcs11-wit.git wit
```

## Dependencies

### Host Adapter

- **wasmtime** - WebAssembly runtime with Component Model support
- **libloading** - Dynamic loading of native PKCS#11 provider libraries
- **wit-bindgen** - Generate Rust bindings from WIT definitions

### Supported PKCS#11 Providers

- SoftHSM2
- Hardware HSMs (YubiHSM, Luna, etc.)
- Any PKCS#11 2.x compliant provider

## Building

```bash
cd host-adapter
cargo build
```

## Testing

The host adapter includes integration tests that can run against a real PKCS#11 provider:

```bash
# Point to your PKCS#11 module
export PKCS11_MODULE_PATH="/opt/homebrew/lib/softhsm/libsofthsm2.so"

# Optional: provide a PIN for testing authenticated operations
export PKCS11_USER_PIN="1234"

cargo test
```

## Usage

```rust
use pkcs11_host_adapter::SlotManagerImpl;

// Initialize with a PKCS#11 provider
SlotManagerImpl::initialize("module=/usr/local/lib/softhsm/libsofthsm2.so")?;

// Use the PKCS#11 interface through WebAssembly components
```

## License

Apache-2.0
