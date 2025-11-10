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

### With Wasmtime CLI Host Bundles

The adapter can be packaged as a wasmtime host bundle for easy distribution:

```bash
# Build host bundle
cd host-adapter
cargo build --release

# Run component with PKCS#11
wasmtime component run \
  --host-bundle ./pkcs11_host_bundle \
  --env PKCS11_MODULE_PATH=/usr/local/lib/softhsm/libsofthsm2.so \
  your_component.wasm
```

See [WASMTIME_INTEGRATION.md](WASMTIME_INTEGRATION.md) for complete integration guide.

### Programmatic Usage

```rust
use pkcs11_host_adapter::AdapterContext;

// Initialize with a PKCS#11 provider
let ctx = AdapterContext::default();
ctx.ensure_initialized("/usr/local/lib/softhsm/libsofthsm2.so")?;

// Use the PKCS#11 interface through WebAssembly components
```

## Integration

This adapter is designed to work with:
- **Wasmtime CLI**: Via host bundles (see [WASMTIME_INTEGRATION.md](WASMTIME_INTEGRATION.md))
- **Custom Runtimes**: Link directly as a Rust library
- **Component Orchestration**: Compatible with webassembly-component-orchestration patterns

## Related Projects

- **wasmtime**: WebAssembly runtime with component model support
- **pkcs11-wit**: WIT interface definitions (submodule)
- **webassembly-component-orchestration**: Component composition system

## License

Apache-2.0
