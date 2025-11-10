# Using PKCS#11 Host Adapter with Wasmtime CLI

This guide explains how to use the PKCS#11 host adapter with the wasmtime CLI's host bundle system.

## Overview

The `pkcs11-wasm/host-adapter` is a **standalone library** that gets packaged as a wasmtime host bundle. Users pass this bundle to wasmtime via the `--host-bundle` flag.

**Important**: This adapter is NOT compiled into wasmtime. It remains a separate, independent library that wasmtime loads dynamically.

## Prerequisites

- Wasmtime with host bundle support (feat/host-interface-bundles branch)
- PKCS#11 library (e.g., SoftHSM2)
- Rust toolchain with wasm32-wasip2 target

## Packaging as a Host Bundle

### Step 1: Build the Host Adapter as a Shared Library

```bash
cd host-adapter
cargo build --release --lib
```

This produces:
- macOS: `target/release/libpkcs11_host_adapter.dylib`
- Linux: `target/release/libpkcs11_host_adapter.so`
- Windows: `target/release/pkcs11_host_adapter.dll`

### Step 2: Create Host Bundle Structure

```bash
mkdir -p pkcs11_host_bundle/{wit,lib}

# Copy the shared library
cp target/release/libpkcs11_host_adapter.{dylib,so} pkcs11_host_bundle/lib/

# Copy WIT definitions
cp -r ../wit/* pkcs11_host_bundle/wit/

# Create host.toml
cat > pkcs11_host_bundle/host.toml <<EOF
[host]
name = "pkcs11"
lib = "lib/libpkcs11_host_adapter.dylib"  # adjust extension for your platform
wit = "wit/worlds/pkcs11.wit"
EOF
```

### Step 3: Use with Wasmtime CLI

```bash
# Run a component with PKCS#11 access
wasmtime component run \
  --host-bundle ./pkcs11_host_bundle \
  --env PKCS11_MODULE_PATH=/usr/local/lib/softhsm/libsofthsm2.so \
  your_component.wasm
```

### Step 4: Create a Manifest (Optional)

For easier reuse, create a `hosts.toml` manifest:

```toml
[global]
search_paths = ["./host-bundles", "~/.wasmtime/hosts"]

[[host]]
name = "pkcs11"
bundle = "pkcs11_host_bundle"

# Or with explicit paths:
# [[host]]
# name = "pkcs11"
# wit = "/opt/pkcs11/wit/worlds/pkcs11.wit"
# lib = "/opt/pkcs11/lib/libpkcs11_host_adapter.so"
```

Then run with:

```bash
wasmtime component run --host-config hosts.toml your_component.wasm
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    User's System                            │
│                                                             │
│  ┌──────────────┐         ┌──────────────────────┐        │
│  │   wasmtime   │ loads   │ pkcs11_host_bundle/  │        │
│  │     CLI      │────────▶│   host.toml          │        │
│  │              │         │   wit/               │        │
│  └──────────────┘         │   lib/libpkcs11.so   │        │
│         │                 └──────────────────────┘        │
│         │                                                  │
│         │ runs                                            │
│         ▼                                                  │
│  ┌──────────────┐                                         │
│  │  Component   │  imports pkcs11:*                       │
│  │   (Wasm)     │                                         │
│  └──────────────┘                                         │
└─────────────────────────────────────────────────────────────┘
```

**Key Point**: wasmtime remains generic. It knows how to load host bundles but has no PKCS#11-specific code. The PKCS#11 functionality comes entirely from the bundle.

## Example Component

Create a WebAssembly component that uses PKCS#11:

### WIT Definition

```wit
// component.wit
package my:crypto@0.1.0;

world my-app {
    // Import PKCS#11 interfaces
    import pkcs11:session/session@0.1.0;
    import pkcs11:crypto/crypto@0.1.0;

    // Export your application interface
    export run: func() -> string;
}
```

### Rust Implementation

```rust
// src/lib.rs
wit_bindgen::generate!({
    world: "my-app",
    path: "../wit",
});

struct Component;

impl Guest for Component {
    fn run() -> String {
        use pkcs11::session::session;
        use pkcs11::crypto::crypto;

        // Open session
        let session_handle = match session::open_session(0, true) {
            Ok(handle) => handle,
            Err(e) => return format!("Failed to open session: {:?}", e),
        };

        // Perform crypto operation
        let data = vec![1, 2, 3, 4, 5];
        let signature = match crypto::sign(
            session_handle,
            0, // key handle
            pkcs11::crypto::crypto::MechanismType::Sha256,
            data.clone()
        ) {
            Ok(sig) => sig,
            Err(e) => {
                let _ = session::close_session(session_handle);
                return format!("Failed to sign: {:?}", e);
            }
        };

        // Clean up
        let _ = session::close_session(session_handle);

        format!("Signature: {} bytes", signature.len())
    }
}

export!(Component);
```

### Build and Run

```bash
# Build component
cargo build --target wasm32-wasip2 --release

# Run with wasmtime
wasmtime component run \
  --host-bundle /path/to/pkcs11_host_bundle \
  --env PKCS11_MODULE_PATH=/usr/local/lib/softhsm/libsofthsm2.so \
  target/wasm32-wasip2/release/my_crypto_app.wasm
```

## Configuration

### Environment Variables

- `PKCS11_MODULE_PATH`: Path to PKCS#11 provider library
- `PKCS11_USER_PIN`: Optional PIN for authenticated operations
- `PKCS11_SLOT_ID`: Slot ID to use (default: 0)

### Bundle Configuration

The `host.toml` can include additional configuration:

```toml
[host]
name = "pkcs11"
lib = "lib/libpkcs11_host_adapter.so"
wit = "wit/worlds/pkcs11.wit"

[host.config]
# Default PKCS#11 module if not specified in environment
module_path = "/usr/local/lib/softhsm/libsofthsm2.so"

# Auto-initialize on load
auto_init = true

# Default slot
default_slot = 0
```

## Testing

### Unit Tests

```bash
cd host-adapter
cargo test
```

### Integration Tests with Real PKCS#11

```bash
# Setup SoftHSM (macOS)
brew install softhsm
mkdir -p ~/softhsm/tokens
softhsm2-util --init-token --slot 0 --label "Test Token" --pin 1234 --so-pin 5678

# Run tests
export PKCS11_MODULE_PATH="/opt/homebrew/lib/softhsm/libsofthsm2.so"
export PKCS11_USER_PIN="1234"
cargo test -- --ignored
```

### End-to-End Test

```bash
# Build test component
cd guest-smoke
cargo build --target wasm32-wasip2 --release

# Run with wasmtime
wasmtime component run \
  --host-bundle ../pkcs11_host_bundle \
  --env PKCS11_MODULE_PATH=/opt/homebrew/lib/softhsm/libsofthsm2.so \
  target/wasm32-wasip2/release/guest_smoke.wasm
```

## Distribution

### Bundle as Tarball

```bash
tar czf pkcs11-host-bundle-v0.1.0-macos.tar.gz pkcs11_host_bundle/
```

### Install System-Wide

```bash
sudo mkdir -p /usr/local/share/wasmtime/hosts
sudo cp -r pkcs11_host_bundle /usr/local/share/wasmtime/hosts/

# Create system manifest
sudo tee /usr/local/share/wasmtime/hosts.toml <<EOF
[global]
search_paths = ["/usr/local/share/wasmtime/hosts"]

[[host]]
name = "pkcs11"
bundle = "pkcs11_host_bundle"
EOF
```

Then users can run:

```bash
wasmtime component run \
  --host-config /usr/local/share/wasmtime/hosts.toml \
  app.wasm
```

## Troubleshooting

### Library Not Found

```bash
# macOS: Check library paths
otool -L libpkcs11_host_adapter.dylib

# Linux: Check library paths
ldd libpkcs11_host_adapter.so

# Ensure PKCS#11 library is accessible
export DYLD_LIBRARY_PATH=/usr/local/lib  # macOS
export LD_LIBRARY_PATH=/usr/local/lib    # Linux
```

### WIT Binding Errors

```bash
# Ensure WIT submodule is initialized
cd pkcs11-wasm
git submodule update --init --recursive

# Rebuild with fresh bindings
cd host-adapter
cargo clean
cargo build
```

### Session Errors

```bash
# Check PKCS#11 module is accessible
export PKCS11_MODULE_PATH="/path/to/libsofthsm2.so"
pkcs11-tool --module $PKCS11_MODULE_PATH --list-slots

# Verify token is initialized
softhsm2-util --show-slots
```

## Security Considerations

1. **Bundle Verification**: Only load bundles from trusted sources
2. **PIN Management**: Never hardcode PINs in bundles or components
3. **Module Paths**: Validate PKCS#11 module paths before loading
4. **Session Lifecycle**: Always close sessions to prevent leaks
5. **Error Handling**: Don't expose sensitive error details to untrusted components

## References

- [Wasmtime Host Bundle Documentation](/path/to/wasmtime/INTEGRATION_GUIDE.md)
- [PKCS#11 Specification](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [Component Model](https://component-model.bytecodealliance.org/)
- [WIT Format](https://github.com/WebAssembly/component-model/blob/main/design/mvp/WIT.md)

## Contributing

See the main [README.md](README.md) for development setup and contribution guidelines.
