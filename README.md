# FIDO2 HMAC Deriver

A command-line application that demonstrates how to use FIDO2 devices to derive HMAC secrets using the HMAC secret extension. 

## Requirements
### System Dependencies

- **Linux** (Ubuntu/Debian recommended)
- **Go 1.21+** - [Download from golang.org](https://golang.org/dl/)
- **libfido2** development libraries
- **pkg-config** for library detection
- **GCC** compiler and build tools

### FIDO2 Device Requirements

- FIDO2 compatible device (YubiKey 5 series, SoloKey, etc.)
- Device connected via USB
- Device PIN configured
- HMAC secret extension support

## Installation

### 1. Install System Dependencies

On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential pkg-config libfido2-dev libudev-dev
```

### 2. Install Go

Download and install Go from [golang.org](https://golang.org/dl/) or use your package manager.

### 3. Clone and Build

```bash
git clone https://github.com/DalexKraus/fido2-hmac-deriver.git
cd fido2-hmac-deriver
./build.sh
```

The build script will:
- Check all dependencies
- Download Go modules
- Build the application
- Verify the build

## Usage

### Basic Usage

Run the application interactively:
```bash
./fido2-hmac-deriver
```

The application will:
1. Search for connected FIDO2 devices
2. Display available devices for selection
3. Prompt for your device PIN
4. Guide you through the HMAC derivation process
5. Display the derived secret in multiple formats

**Example Output:**
```
❯ ./fido2-hmac-deriver
FIDO2 HMAC Secret Deriver
=========================

Deriving cryptographic secrets using FIDO2/CTAP devices.
Ensure your FIDO2 device is connected via USB.

[~] Searching for FIDO2 devices...
[+] Found 1 FIDO2 device(s)
Available FIDO2 Devices:
========================

[1] YubiKey OTP+FIDO+CCID by Yubico
    Path: /dev/hidraw10

Please select a device [1-1]: 1
[+] Selected device: YubiKey OTP+FIDO+CCID (Yubico)
[~] Validating device accessibility...
Enter your FIDO2 device PIN:
[~] Validating configuration...
[~] Starting HMAC secret derivation process...
[~] You will need to touch your FIDO2 device when it blinks
[~] Connecting to FIDO2 device...
[~] Generating deterministic salt...
[~] Found existing credential in 59NXLO-tdnm9844v.cred
[~] Using existing credential...
[~] Deriving HMAC secret (please touch your device when it blinks)...
[+] HMAC secret derived successfully!

HMAC Secret Derivation Complete!
=================================

Device Information:
   Name: YubiKey OTP+FIDO+CCID
   Manufacturer: Yubico
   Path: /dev/hidraw10

Operation Details:
   Relying Party: e2e-git
   Timestamp: 2025-08-05T10:36:27+02:00
   Duration: 0s

Derived Secret:
   Base64: hrV3kzj6MfY9yehhFh4yPth+YHe+j/wE6TUZVaGM4gU=
   Hex:    86b5779338fa31f63dc9e861161e323ed87e6077be8ffc04e9351955a18ce205
   Length: 32 bytes (256 bit)

Salt Used:
   Base64: JnEQFaScEwM4tAqEx0jCXRn/Il3vO3lXcWftJS0CdqQ=
   Hex:    26711015a49c130338b40a84c748c25d19ff225def3b79577167ed252d0276a4
   Length: 32 bytes

Credential Information:
   ID (Base64): 59NXLO+tdnm9844vaFkM0ygpqySdj4e9mgwK0LWRMstb/IE3RQFH3IL+vUFEQa0Q
   ID (Hex):    e7d3572cefad7679bdf38e2f68590cd32829ab249d8f87bd9a0c0ad0b59132cb5bfc8137450147dc82febd414441ad10
   Length:      48 bytes

Security Information:
   Secret Fingerprint:     86b57793...a18ce205
   Salt Fingerprint:       26711015...2d0276a4
   Credential Fingerprint: e7d3572c...4441ad10

Usage Notes:
   - The derived secret is unique to this device and salt combination
   - Store the salt securely if you need to reproduce this secret
   - The credential is stored on your FIDO2 device
   - This secret can be used for encryption, authentication, or key derivation
```

### Non-Interactive Mode

For automation and scripting, you can run the application in non-interactive mode by specifying the device path and PIN via environment variable:

```bash
# Set PIN in environment variable
export MY_FIDO_PIN="123456"

# Run non-interactively
./fido2-hmac-deriver --fido-device=/dev/hidraw10 --pin-environment-variable=MY_FIDO_PIN
(will produce the same output as the interactive mode, but without prompts)
```

### Scripting Mode

For integration with other tools, combine non-interactive mode with the `--key-only` flag.
This outputs only the derived key to stdout, making it suitable for piping to other commands:

```bash
# Example: Extract just the key for use in other tools
export MY_FIDO_PIN="123456"
./fido2-hmac-deriver --fido-device=/dev/hidraw10 --pin-environment-variable=MY_FIDO_PIN --key-only | grep -A1 "BEGIN DERIVED KEY" | tail -n1
hrV3kzj6MfY9yehhFh4yPth+YHe+j/wE6TUZVaGM4gU=
```

### Command Line Options

- `--key-only`: Output only the derived key to stdout (useful for scripting)
- `--fido-device=<path>`: Specify FIDO device path (e.g., `/dev/hidraw10`) to skip device selection
- `--pin-environment-variable=<name>`: Environment variable name containing the PIN (for non-interactive mode)
- `--help`: Display help information

## Testing
To verify a deterministic key derivation, you can run the following script:
```bash
./test.sh
```

## Device Setup

### YubiKey Setup

1. **Insert your YubiKey** into a USB port
2. **Set a PIN** if not already configured:
   ```bash
   ykman fido access change-pin
   ```
3. **Verify HMAC support**:
   ```bash
   ykman fido info
   ```

## Architecture

The application is separated into multiple smaller modules:

- **`main.go`**: Application entry point
- **`internal/device/`**: FIDO2 device discovery and management
- **`internal/crypto/`**: HMAC secret derivation and cryptographic operations
- **`internal/ui/`**: User interface and display formatting
- **`internal/types/`**: Type definitions and interfaces

### Dependencies

- **[go-libfido2](https://github.com/keys-pub/go-libfido2)**: Go bindings for libfido2
- **[color](https://github.com/fatih/color)**: Colored terminal output
- **[term](https://golang.org/x/term)**: Terminal utilities for secure input
