[![Watch a one-minute video tour of stse-linux](https://gitdiagram.com/video-badge.svg)](https://gitdiagram.com/stmicroelectronics/stse-linux/video)

# STSAFE-A / STSAFE-L Linux Middleware

Userspace middleware and OpenSSL 3.x providers for **STSAFE-A110**, **STSAFE-A120**, and **STSAFE-L010** secure elements on Linux/MPU platforms (STM32MP1, Raspberry Pi, and standard embedded Linux).

---

## ⚡ Quick Start & Platform Guides

Follow the guide tailored to your target platform or check the FAQ:

- 🚀 **[Raspberry Pi Quick Start Guide](doc/rpi_quick_start_guide.md)** — Native build on Raspberry Pi OS, 40-pin GPIO pinout, cross-compilation, and testing.
- 🐧 **[STM32MP1 Quick Start Guide](doc/stm32MP1_quick_start_guide.md)** — OpenSTLinux SDK setup, cross-compilation, and automated SSH deployment.
- ❓ **[Troubleshooting & FAQ](doc/troubleshooting_and_faq.md)** — Common questions, I²C error codes, `se-daemon` issues, OpenSSL provider troubleshooting, and slot permission solutions.

---

## 📖 Table of Contents

- [What is stse-linux?](#what-is-stse-linux)
- [Repository Layout](#repository-layout)
- [Architecture & Design](#architecture--design)
- [Supported Devices](#supported-devices)
- [Build Configuration (CMake)](#build-configuration-cmake)
- [Examples Catalog](#examples-catalog)
- [OpenSSL 3.x Provider Integration](#openssl-3x-provider-integration)
- [Documentation & FAQ Links](#documentation--faq-links)

---

## What is stse-linux?

`stse-linux` provides the complete userspace stack needed to integrate STSAFE secure elements into Linux systems:

- **`se-daemon`**: A privilege-separated I²C proxy daemon. It runs as root, exclusively manages `/dev/i2c-n`, and exposes a secure Unix domain socket (`/var/run/se-daemon.sock`). Unprivileged user applications can communicate with the secure element without direct raw I²C hardware access permissions.
- **`libstse.so`**: The shared C library providing high-level STSAFE cryptographic and storage APIs (built from STMicroelectronics' `STSELib` adapted for Linux IPC).
- **OpenSSL 3.x Providers**: Standard dynamically loadable provider modules (`stsafe-a120.so`, `stsafe-a110.so`, `stsafe-l010.so`) enabling hardware-backed ECDSA / Ed25519 signing, verification, and key generation via standard OpenSSL `EVP_*` APIs.

---

## Repository Layout

```
stse-linux/
├── CMakeLists.txt                  Top-level build system
├── README.md                       Main overview and guide
├── cmake/                          Cross-compilation toolchain files (STM32MP1, Raspberry Pi)
├── daemon/
│   ├── se_daemon.c                 Privileged I²C proxy daemon
│   └── se-daemon.service           systemd service unit
├── doc/
│   ├── rpi_quick_start_guide.md    Raspberry Pi setup, wiring & build guide
│   ├── stm32MP1_quick_start_guide.md STM32MP1 OpenSTLinux build & deploy guide
│   ├── stse_linux_training_manual.md Comprehensive training manual & assignments
│   └── troubleshooting_and_faq.md  Troubleshooting, FAQ & error codes
├── lib/
│   ├── STSELib/                    STMicroelectronics STSAFE core library (submodule)
│   └── STSELib_Platform/           Linux IPC platform adaptation layer
├── providers/
│   ├── stse_provider.h             Shared provider parameter definitions
│   ├── stsafe-a120_provider.c      OpenSSL 3.x provider for STSAFE-A120
│   ├── stsafe-a110_provider.c      OpenSSL 3.x provider for STSAFE-A110
│   └── stsafe-l010_provider.c      OpenSSL 3.x provider for STSAFE-L010
└── examples/
    ├── stsafe-a110/                Examples for STSAFE-A110
    ├── stsafe-a120/                Examples for STSAFE-A120
    └── stsafe-l010/                Examples for STSAFE-L010
```

---

## Architecture & Design

### Software Stack

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                 User Application                                 │
│                      (OpenSSL 3.x EVP API  /  STSELib API)                       │
├─────────────────────────┬────────────────────────────┬───────────────────────────┤
│     stsafe-a120.so      │       stsafe-a110.so       │       stsafe-l010.so      │
│   STSAFE-A120           │     STSAFE-A110            │     STSAFE-L010           │
│   OpenSSL Provider      │     OpenSSL Provider       │     OpenSSL Provider      │
│   NIST/Brainpool ECDSA  │     NIST/Brainpool ECDSA   │     Ed25519 sign (HW)     │
│   sign + verify (HW)    │     sign + verify (HW)     │     Ed25519 verify (SW)   │
├─────────────────────────┴────────────────────────────┴───────────────────────────┤
│                                  libstse.so                                      │
│                        (STSELib  +  Linux IPC platform layer)                    │
├──────────────────────────────────────────────────────────────────────────────────┤
│                    Unix domain socket  /var/run/se-daemon.sock                   │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                   se-daemon                                      │
│                   (runs as root, owns /dev/i2c-N, no STSELib)                    │
├──────────────────────────────────────────────────────────────────────────────────┤
│                           Linux I²C kernel driver  /dev/i2c-N                    │
├──────────────────────────────────────────────────────────────────────────────────┤
│   STSAFE-A120 / STSAFE-A110 (bus 1, I²C addr 0x20)                               │
│   STSAFE-L010               (bus 1, I²C addr 0x0C)                               │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Key Design Highlights

| Feature | Description |
|---|---|
| **Privilege Separation** | `se-daemon` owns `/dev/i2c-n`; user applications communicate over Unix socket without root permissions. |
| **Concurrency & Thread Safety** | All I²C bus transactions are queued and serialized safely by `se-daemon`, preventing race conditions across multi-threaded or multi-process applications. |
| **OpenSSL 3.x Native Integration** | Hardware crypto is exposed through modern OpenSSL 3.x provider architecture; zero custom API lock-in for crypto applications. |
| **Transparent Fallback (L010)** | STSAFE-L010 performs hardware Ed25519 signing; signature verification is automatically and transparently delegated to OpenSSL's built-in software provider. |

---

## Supported Devices

| Secure Element | 7-bit I²C Address | Default Bus | Key Cryptographic Features |
|---|---|---|---|
| **STSAFE-A120** | `0x20` | `/dev/i2c-1` | ECDSA sign/verify (NIST P-256/384/521, Brainpool P-256/384/512), ECDH, X25519, Ed25519, AES keys, Secure Storage |
| **STSAFE-A110** | `0x20` | `/dev/i2c-1` | ECDSA sign/verify (NIST P-256/384, Brainpool P-256/384), ECDH, Key wrapping, Secure Storage |
| **STSAFE-L010** | `0x0C` | `/dev/i2c-1` | Ed25519 sign (HW), Key generation, Secure Storage (no wake-up sequence required) |

> [!TIP]
> Both an STSAFE-A (addr `0x20`) and an STSAFE-L (addr `0x0C`) can reside simultaneously on the same I²C bus since their 7-bit addresses do not collide.

---

## Build Configuration (CMake)

The build system supports building for specific secure elements or all devices simultaneously:

| Option | Type | Default | Description |
|---|---|---|---|
| `TARGET_DEVICE` | `STRING` | `ALL` | Device to build for: `ALL`, `STSAFE_A120`, `STSAFE_A110`, or `STSAFE_L010` |
| `BUILD_EXAMPLES` | `BOOL` | `ON` | Build example programs |
| `BUILD_PROVIDER` | `BOOL` | `ON` | Build OpenSSL 3.x provider modules (`stsafe-*.so`) |
| `ENABLE_GTK_DEMO` | `BOOL` | `ON` | Build GTK3 GUI demo (`06_GTK_Authentication_Demo`) if `gtk+-3.0` is present |
| `DEPLOY_TARGET` | `STRING` | `root@stm32mp1` | SSH target for `make deploy` (`user@host` or `user@ip`) |
| `DEPLOY_EXAMPLES_DIR` | `PATH` | `/home/root/stse-linux` | Remote directory for binaries (e.g. `/home/pi/stse-linux` on Raspberry Pi) |
| `OPENSSL_MODULES_INSTALL_DIR` | `PATH` | *(auto)* | Custom provider install path. Leave empty to auto-detect via `openssl version -a` |
| `CMAKE_TOOLCHAIN_FILE` | `PATH` | *(none)* | `cmake/stm32mp1-toolchain.cmake` or `cmake/rpi-toolchain.cmake` (omit for native build) |

---

## Examples Catalog

The repository includes ready-to-run examples located under `examples/`:

### STSAFE-A120 Examples
| Executable | Purpose |
|---|---|
| `01_Echo_loop` | I²C communication & loopback test |
| `01_Hash` | Hardware SHA hashing |
| `01_Random_number` | Hardware True Random Number Generator (TRNG) |
| `01_Device_authentication` | Reads device X.509 certificate and verifies certificate chain |
| `01_Key_pair_generation_NIST_P256` | Generates ECC key pair (NIST P-256) |
| `01_Key_pair_generation_NIST_P521` | Generates ECC key pair (NIST P-521) |
| `01_Key_pair_generation_BRAINPOOL_P512` | Generates Brainpool key pair |
| `01_Secure_data_storage_zone_access` | Read/write secure zones |
| `01_Secure_data_storage_counter_access` | Monotonic counter read/increment |
| `02_OpenSSL_ecdsa_sign_verify` | **OpenSSL 3 provider demo**: Hardware ECDSA sign and verify |
| `03_ECDH` | Elliptic-Curve Diffie-Hellman key exchange |
| `06_GTK_Authentication_Demo` | Interactive GTK3 authentication visual demo |

### STSAFE-A110 Examples
Includes core features: `01_Echo_loop`, `01_Hash`, `01_Device_authentication`, `01_Key_pair_generation_NIST_P256`, `01_Key_pair_generation_NIST_P384`, `02_OpenSSL_ecdsa_sign_verify`, `03_ECDH`, `03_Key_wrapping`, etc.

### STSAFE-L010 Examples
| Executable | Purpose |
|---|---|
| `01_Echo_loop` | Connectivity test |
| `01_Device_authentication` | Read certificate and verify device signature |
| `01_Secure_data_storage` | Read/write secure data storage |
| `02_OpenSSL_eddsa_sign` | **OpenSSL 3 provider demo**: Hardware Ed25519 signing + delegated software verify |

---

## OpenSSL 3.x Provider Integration

Using STSAFE in your own C applications via standard OpenSSL `EVP_*` APIs requires loading the provider and specifying `provider=<name>`.

### Provider Overview

| Provider | Module Name | Supported Algorithms |
|---|---|---|
| **STSAFE-A120** | `stsafe-a120.so` | `EC` keymgmt, `ECDSA` (NIST P-256/384/521, Brainpool P-256/384/512), `X25519` |
| **STSAFE-A110** | `stsafe-a110.so` | `EC` keymgmt, `ECDSA` (NIST P-256/384, Brainpool P-256/384) |
| **STSAFE-L010** | `stsafe-l010.so` | `ED25519` keymgmt, `EdDSA` sign (HW), `EdDSA` verify (SW fallback) |

### Code Example (STSAFE-A120 / STSAFE-A110 ECDSA Sign & Verify)

```c
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include "providers/stse_provider.h"

int main(void) {
    /* 1. Load STSAFE provider and default software provider */
    OSSL_PROVIDER *prov_stsafe = OSSL_PROVIDER_load(NULL, "stsafe-a120");
    OSSL_PROVIDER *prov_default = OSSL_PROVIDER_load(NULL, "default");

    /* 2. Configure target hardware slot (e.g., slot 1) and I2C bus (bus 1) */
    uint32_t slot = 1, bus = 1;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_uint32(STSE_PROV_PARAM_SLOT, &slot),
        OSSL_PARAM_construct_uint32(STSE_PROV_PARAM_BUS,  &bus),
        OSSL_PARAM_construct_end()
    };

    /* 3. Generate key pair inside the secure element */
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=stsafe-a120");
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_params(kctx, params);
    EVP_PKEY *hw_key = NULL;
    EVP_PKEY_generate(kctx, &hw_key);
    EVP_PKEY_CTX_free(kctx);

    /* 4. Hardware sign */
    unsigned char message[] = "Hello STSAFE Secure World!";
    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit_ex(sign_ctx, NULL, "SHA2-256", NULL, "provider=stsafe-a120", hw_key, NULL);
    size_t sig_len = 0;
    EVP_DigestSign(sign_ctx, NULL, &sig_len, message, sizeof(message));
    unsigned char *sig = malloc(sig_len);
    EVP_DigestSign(sign_ctx, sig, &sig_len, message, sizeof(message));
    EVP_MD_CTX_free(sign_ctx);

    /* 5. Hardware verify */
    EVP_MD_CTX *vfy_ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit_ex(vfy_ctx, NULL, "SHA2-256", NULL, "provider=stsafe-a120", hw_key, NULL);
    int valid = EVP_DigestVerify(vfy_ctx, sig, sig_len, message, sizeof(message));
    printf("Signature status: %s\n", valid == 1 ? "VALID" : "INVALID");
    EVP_MD_CTX_free(vfy_ctx);

    /* 6. Cleanup */
    free(sig);
    EVP_PKEY_free(hw_key);
    OSSL_PROVIDER_unload(prov_stsafe);
    OSSL_PROVIDER_unload(prov_default);
    return 0;
}
```

**Build application**:
```bash
gcc -o app app.c -lssl -lcrypto -I path/to/stse-linux/providers
export OPENSSL_MODULES=/usr/lib/ossl-modules
./app
```

---

## Documentation & FAQ Links

- 📖 **[Raspberry Pi Quick Start Guide](doc/rpi_quick_start_guide.md)**
- 📖 **[STM32MP1 Quick Start Guide](doc/stm32MP1_quick_start_guide.md)**
- ❓ **[Troubleshooting & FAQ Guide](doc/troubleshooting_and_faq.md)**
