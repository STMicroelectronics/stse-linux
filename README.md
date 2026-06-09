# STSAFE-A STSAFE-L Linux Middleware

Userspace middleware for **STSAFE-A120** and **STSAFE-L010** secure elements on Linux/MPU platforms.
It provides:

- **`se-daemon`** — A privilege-separated I²C bus proxy that owns `/dev/i2c-n` and exposes a Unix domain socket to unprivileged applications.
- **`libstse.so`** — The full STSELib shared library, linked by applications that communicate with the secure element via the daemon.
- **`stsafea.so`** — An OpenSSL 3.x provider for **STSAFE-A120**: hardware-backed ECDSA key generation, signing, and verification (NIST P-256/384/521, Brainpool).
- **`stsafel.so`** — An OpenSSL 3.x provider for **STSAFE-L010**: hardware Ed25519 signing, software-delegated verification.

---

## Table of Contents

1. [Repository Architecture](#repository-architecture)
2. [Hardware Prerequisites](#hardware-prerequisites)
3. [Software Prerequisites](#software-prerequisites)
4. [Getting Started](#getting-started)
5. [CMake Options Reference](#cmake-options-reference)
6. [Building for STSAFE-A120](#building-for-stsafe-a120)
7. [Building for STSAFE-L010](#building-for-stsafe-l010)
8. [Building for Both Devices](#building-for-both-devices)
9. [OpenSSL 3.x Provider Integration](#openssl-3x-provider-integration)
10. [Troubleshooting](#troubleshooting)

---

## Repository Architecture

```
stse-linux/
├── CMakeLists.txt                  Top-level build system (see §CMake Options)
├── README.md
├── cmake/
│   └── stm32mp1-toolchain.cmake    STM32MP1 cross-compilation toolchain file
├── daemon/
│   ├── se_daemon.c                 Privileged I²C proxy daemon
│   └── se-daemon.service           systemd unit file
├── lib/
│   ├── STSELib/                    STMicroelectronics STSAFE library (git submodule)
│   └── STSELib_Platform/           Linux IPC platform adaptation layer
├── providers/
│   ├── stse_provider.h             Shared provider parameter definitions
│   ├── stsafea_provider.c          OpenSSL 3.x provider — STSAFE-A120
│   └── stsafel_provider.c          OpenSSL 3.x provider — STSAFE-L010
└── examples/
    ├── stsafe-a120/                STSAFE-A120 example programs
    │   ├── apps_utils/             Shared utility code for A120 examples
    │   ├── 01_Echo_loop/
    │   ├── 01_Hash/
    │   ├── 01_Random_number/
    │   ├── 01_Device_authentication/
    │   ├── 01_Device_authentication_multi_steps/
    │   ├── 01_Key_pair_generation_NIST_P256/
    │   ├── 01_Key_pair_generation_NIST_P521/
    │   ├── 01_Key_pair_generation_BRAINPOOL_P512/
    │   ├── 01_Key_pair_generation_EDWARDS_25519/
    │   ├── 01_Secure_data_storage_{zone,counter}_access/
    │   ├── 02_Command_AC_provisioning/
    │   ├── 02_Host_key_provisioning/
    │   ├── 02_Host_key_provisioning_wrapped/
    │   ├── 02_OpenSSL_ecdsa_sign_verify/   ← stsafea provider demo
    │   ├── 03_ECDH/
    │   ├── 03_Key_wrapping/
    │   ├── 04_Symmetric_key_provisioning_control_fields/
    │   ├── 05_Symmetric_key_establishment_*/
    │   └── 06_GTK_Authentication_Demo/
    └── stsafe-l010/                STSAFE-L010 example programs
        ├── apps_utils/             Shared utility code for L010 examples
        ├── 01_Echo_loop/
        ├── 01_Device_authentication/
        ├── 01_Device_authentication_multi_steps/
        ├── 01_Secure_data_storage/
        └── 02_OpenSSL_eddsa_sign/          ← stsafel provider demo
```

### Software Stack

```
┌──────────────────────────────────────────────────────────────────────┐
│                        User Application                              │
│             (OpenSSL 3.x EVP API  /  STSELib API)                   │
├─────────────────────────┬────────────────────────────────────────────┤
│     stsafea.so          │         stsafel.so                        │
│   STSAFE-A120           │       STSAFE-L010                         │
│   OpenSSL Provider      │       OpenSSL Provider                    │
│   NIST/Brainpool ECDSA  │       Ed25519 sign (HW)                   │
│   sign + verify (HW)   │       Ed25519 verify (SW default provider) │
├─────────────────────────┴────────────────────────────────────────────┤
│                         libstse.so                                   │
│               (STSELib  +  Linux IPC platform layer)                │
├──────────────────────────────────────────────────────────────────────┤
│           Unix domain socket  /var/run/se-daemon.sock                │
├──────────────────────────────────────────────────────────────────────┤
│                          se-daemon                                   │
│          (runs as root, owns /dev/i2c-N, no STSELib)                │
├──────────────────────────────────────────────────────────────────────┤
│                  Linux I²C kernel driver  /dev/i2c-N                 │
├──────────────────────────────────────────────────────────────────────┤
│   STSAFE-A120  (bus 1, I²C addr 0x20)                                │
│   STSAFE-L010  (bus 1, I²C addr 0x0C)                                │
└──────────────────────────────────────────────────────────────────────┘
```

**Key design decisions**

| Concern | Decision |
|---|---|
| I²C privilege | `se-daemon` runs as root; applications connect via socket (no direct `/dev/i2c-N` access needed) |
| Thread safety | `se-daemon` serializes all I²C frames; library calls are multi-process safe |
| OpenSSL integration | Providers are `MODULE` shared objects; loaded at runtime via `OSSL_PROVIDER_load()`, never linked |
| L010 verify limitation | STSAFE-L010 hardware cannot verify arbitrary signatures; `stsafel` provider transparently delegates verify to OpenSSL's `default` software provider |

---

## Hardware Prerequisites

### STSAFE-A120

| Parameter | Value |
|---|---|
| Interface | I²C |
| 7-bit address | `0x20` |
| Typical bus | `/dev/i2c-1` (bus ID `1`) |
| Supported curves | NIST P-256, P-384, P-521 · Brainpool P-256, P-384, P-512 · X25519 · Ed25519 |
| Supported operations | Sign, Verify, Key generation, ECDH, Symmetric key, Secure storage |

### STSAFE-L010

| Parameter | Value |
|---|---|
| Interface | I²C |
| 7-bit address | `0x0C` |
| Typical bus | `/dev/i2c-1` (bus ID `1`) |
| Supported curves | Ed25519 only |
| Supported operations | Sign (hardware), Key generation, Secure storage |
| Wake-up sequence | **None required** |

> [!NOTE]
> If both devices are connected to the same board, they can share the same I²C bus (address space is different). The bus ID and device address are configured per call via `STSE_PROV_PARAM_BUS` and `STSE_PROV_PARAM_SLOT` parameters.

### Verifying I²C connectivity

On the target board, scan the bus to confirm device presence:

```bash
# Install i2c-tools if not present
opkg install i2c-tools   # OpenSTLinux
# or
apt install i2c-tools    # Debian/Ubuntu

# Scan bus 1
i2cdetect -y 1
```

Expected output:
- `0x20` present → STSAFE-A120 detected
- `0x0c` present → STSAFE-L010 detected

---

## Software Prerequisites

### Build host

| Requirement | Minimum version | Install (Ubuntu/Debian) |
|---|---|---|
| CMake | 3.18 | `apt install cmake` |
| GCC or Clang | any recent | `apt install build-essential` |
| OpenSSL dev headers | 3.x | `apt install libssl-dev` |
| Git | any | `apt install git` |
| OpenSSH client | any | `apt install openssh-client` |
| tar | any | pre-installed |

### Cross-compilation toolchain (STM32MP1 target)

Two modes are supported by `cmake/stm32mp1-toolchain.cmake`:

**Mode A — OpenSTLinux SDK (recommended)**

Download the SDK from [st.com](https://www.st.com) and install it:
```bash
chmod +x en.stm32mp1-openstlinux-<ver>-developer-sdk.sh
./en.stm32mp1-openstlinux-<ver>-developer-sdk.sh
```

Source the environment before every build session:
```bash
source /opt/st/stm32mp1/<ver>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
```
The SDK sets `CC`, `CXX`, `OECORE_TARGET_SYSROOT` and pkg-config paths; the toolchain file picks them up automatically.

**Mode B — Generic ARM hard-float toolchain**

```bash
apt install gcc-arm-linux-gnueabihf
# Then pass CROSS_COMPILE to cmake:
cmake -B build/stsafe-a \
      -DCMAKE_TOOLCHAIN_FILE=cmake/stm32mp1-toolchain.cmake \
      -DCROSS_COMPILE=arm-linux-gnueabihf- \
      ...
```

> [!IMPORTANT]
> Mode B requires that OpenSSL 3.x cross-compiled libraries and headers be present in the toolchain sysroot. Mode A (SDK) includes them automatically.

### Target board (runtime)

| Requirement | Notes |
|---|---|
| Linux kernel ≥ 4.15 | I²C character device driver (`/dev/i2c-N`) |
| OpenSSL 3.x runtime | `libssl.so.3`, `libcrypto.so.3` |
| systemd | For `se-daemon` service management |
| SSH server | For the `deploy` CMake target |
| `/dev/i2c-1` accessible | Kernel `i2c-dev` module must be loaded |

Ensure the I²C module is loaded at boot:
```bash
# On target
echo "i2c-dev" >> /etc/modules-load.d/i2c.conf
```

---

## Getting Started

### 1. Clone and initialize submodules

```bash
git clone https://github.com/STMicroelectronics/stse-linux.git
cd stse-linux
git submodule update --init lib/STSELib
cd lib/STSELib && git checkout remotes/origin/feature/pkcs11 && cd -
```

### 2. (Cross-compilation) Source the SDK environment

```bash
source /opt/st/stm32mp1/<ver>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
```

> [!IMPORTANT]
> This step is required **every time** you open a new terminal. The environment variables it sets (`CC`, sysroot paths, pkg-config) are needed by CMake.

---

## CMake Options Reference

| Option | Type | Default | Description |
|---|---|---|---|
| `TARGET_DEVICE` | `STRING` | `ALL` | Device profile: `ALL`, `STSAFE_A` (A120 only), `STSAFE_L` (L010 only) |
| `BUILD_EXAMPLES` | `BOOL` | `ON` | Build all example programs |
| `BUILD_PROVIDER` | `BOOL` | `ON` | Build OpenSSL 3.x provider modules |
| `ENABLE_GTK_DEMO` | `BOOL` | `ON` | Build `06_GTK_Authentication_Demo` (requires `gtk+-3.0`) |
| `DEPLOY_TARGET` | `STRING` | `root@stm32mp1` | SSH destination for the `deploy` target (`user@host` or `user@ip`) |
| `DEPLOY_EXAMPLES_DIR` | `PATH` | `/home/root/stse-linux` | Remote base directory for example binaries (`stsafe-a/` and `stsafe-l/` sub-dirs created automatically) |
| `OPENSSL_MODULES_INSTALL_DIR` | `PATH` | *(auto)* | Override provider `.so` install path. Empty = auto-detect via `openssl version -a` (`MODULESDIR`) |
| `CMAKE_TOOLCHAIN_FILE` | `PATH` | *(none)* | Point to `cmake/stm32mp1-toolchain.cmake` for cross-compilation |

---

## Building for STSAFE-A120

### Configure

```bash
# Source the SDK (cross-compilation only)
source /opt/st/stm32mp1/<ver>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi

cmake -B build/stsafe-a \
      -DCMAKE_TOOLCHAIN_FILE=cmake/stm32mp1-toolchain.cmake \
      -DTARGET_DEVICE=STSAFE_A \
      -DDEPLOY_TARGET=root@<board-ip>
```

> [!NOTE]
> Omit `-DCMAKE_TOOLCHAIN_FILE=...` for a native (host-architecture) build, e.g. for development on an x86 Linux board running the same OS as the target.

### Build

```bash
cmake --build build/stsafe-a
```

Build outputs in `build/stsafe-a/`:

```
build/stsafe-a/
├── se-daemon                    I²C privilege daemon
├── libstse.so / libstse.so.1*   STSELib shared library
├── stsafea.so                   OpenSSL 3.x provider module
├── 01_Echo_loop                 ┐
├── 01_Device_authentication     │
├── 01_Hash                      │ STSAFE-A120 example binaries
├── ...                          │
├── 02_OpenSSL_ecdsa_sign_verify ┘ (provider demo)
└── 06_GTK_Authentication_Demo   (if GTK3 was found)
```

### Deploy to target

```bash
cmake --build build/stsafe-a --target deploy
```

The `deploy` target (over SSH):
1. Stops `se-daemon` on the target
2. Uploads `se-daemon` → `/usr/local/sbin/se-daemon`
3. Uploads `libstse.so.1.0` → `/usr/local/lib/` (with symlinks + `ldconfig`)
4. Uploads `stsafea.so` → OpenSSL MODULESDIR (auto-detected)
5. Uploads all A120 example binaries → `${DEPLOY_EXAMPLES_DIR}/stsafe-a/`
6. Uploads `se-daemon.service` → `/etc/systemd/system/`
7. Enables and starts `se-daemon`

> [!TIP]
> Passwordless SSH (key-based auth) is strongly recommended. Set it up with:
> ```bash
> ssh-copy-id root@<board-ip>
> ```

### Run STSAFE-A120 examples

```bash
# On the target board
cd /home/root/stse-linux/stsafe-a

# Basic I²C communication test
./01_Echo_loop

# Hash operation
./01_Hash

# Key pair generation (NIST P-256, slot 0, bus 1)
./01_Key_pair_generation_NIST_P256

# Device authentication (reads device certificate, verifies chain)
./01_Device_authentication

# OpenSSL ECDSA sign + hardware verify demo
export OPENSSL_MODULES=/usr/lib/ossl-modules
./02_OpenSSL_ecdsa_sign_verify [busID [slotID]]
# Example: ./02_OpenSSL_ecdsa_sign_verify 1 1
#   (slot 0 may have Access Condition restrictions — use slot 1 if keygen returns error 0x11)
```

#### A120 example catalogue

| Binary | Description |
|---|---|
| `01_Echo_loop` | Basic I²C loopback / connectivity test |
| `01_Hash` | Hardware SHA hash |
| `01_Random_number` | Hardware RNG |
| `01_Device_authentication` | Certificate read + chain verification |
| `01_Device_authentication_multi_steps` | Multi-step authentication protocol |
| `01_Key_pair_generation_NIST_P256` | ECC key pair generation on NIST P-256 |
| `01_Key_pair_generation_NIST_P521` | ECC key pair generation on NIST P-521 |
| `01_Key_pair_generation_BRAINPOOL_P512` | ECC key pair generation on Brainpool P-512 |
| `01_Key_pair_generation_EDWARDS_25519` | Ed25519 key pair generation |
| `01_Secure_data_storage_zone_access` | Secure zone read/write |
| `01_Secure_data_storage_counter_access` | Monotonic counter read/increment |
| `02_Command_AC_provisioning` | Access condition provisioning |
| `02_Host_key_provisioning` | Host key slot provisioning |
| `02_Host_key_provisioning_wrapped` | Wrapped host key provisioning |
| `02_OpenSSL_ecdsa_sign_verify` | **OpenSSL provider demo** — ECDSA HW sign + HW verify |
| `03_ECDH` | Elliptic-curve Diffie-Hellman |
| `03_Key_wrapping` | Key wrapping / unwrapping |
| `04_Symmetric_key_provisioning_control_fields` | Symmetric key slot control |
| `05_Symmetric_key_establishment_compute_AES-128_CMAC` | AES-128 CMAC establishment |
| `05_Symmetric_key_establishment_encrypt_AES-256_CCM` | AES-256 CCM establishment |
| `05_Symmetric_key_provisioning_wrapped_*` | Wrapped symmetric key provisioning |
| `06_GTK_Authentication_Demo` | GTK3 GUI authentication demo (if built) |

---

## Building for STSAFE-L010

### Configure

```bash
source /opt/st/stm32mp1/<ver>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi

cmake -B build/stsafe-l \
      -DCMAKE_TOOLCHAIN_FILE=cmake/stm32mp1-toolchain.cmake \
      -DTARGET_DEVICE=STSAFE_L \
      -DDEPLOY_TARGET=root@<board-ip>
```

### Build

```bash
cmake --build build/stsafe-l
```

Build outputs in `build/stsafe-l/`:

```
build/stsafe-l/
├── se-daemon
├── libstse.so / libstse.so.1*
├── stsafel.so                   OpenSSL 3.x provider module
├── 01_Echo_loop
├── 01_Device_authentication
├── 01_Device_authentication_multi_steps
├── 01_Secure_data_storage
└── 02_OpenSSL_eddsa_sign        (provider demo)
```

### Deploy to target

```bash
cmake --build build/stsafe-l --target deploy
```

This deploys `stsafel.so` and all L010 example binaries to `${DEPLOY_EXAMPLES_DIR}/stsafe-l/`.

### Run STSAFE-L010 examples

```bash
# On the target board
cd /home/root/stse-linux/stsafe-l

# Basic connectivity test
./01_Echo_loop

# Device authentication
./01_Device_authentication

# Secure data storage
./01_Secure_data_storage

# OpenSSL Ed25519 sign (HW) + verify (SW) demo
export OPENSSL_MODULES=/usr/lib/ossl-modules
./02_OpenSSL_eddsa_sign [busID [slotID]]
# Example: ./02_OpenSSL_eddsa_sign 1
```

#### L010 example catalogue

| Binary | Description |
|---|---|
| `01_Echo_loop` | Basic I²C loopback / connectivity test |
| `01_Device_authentication` | Certificate read + Ed25519 signature verification |
| `01_Device_authentication_multi_steps` | Multi-step authentication |
| `01_Secure_data_storage` | Secure zone read/write |
| `02_OpenSSL_eddsa_sign` | **OpenSSL provider demo** — Ed25519 HW sign + SW verify |

> [!NOTE]
> STSAFE-L010 does not perform signature verification in hardware. The `stsafel` provider transparently delegates verify to OpenSSL's built-in `default` provider. This is handled internally; application code uses the same standard `EVP_DigestVerify*` API.

---

## Building for Both Devices

Use `TARGET_DEVICE=ALL` (the default) to build everything in a single configuration. To avoid binary name conflicts (both devices share example names like `01_Echo_loop`), the build system places examples in device-specific subdirectories:

```
build/all/
├── se-daemon               (shared infrastructure)
├── libstse.so*
├── stsafea.so
├── stsafel.so
├── stsafe-a/               STSAFE-A120 examples
│   ├── 01_Echo_loop
│   ├── 02_OpenSSL_ecdsa_sign_verify
│   └── ...
└── stsafe-l/               STSAFE-L010 examples
    ├── 01_Echo_loop
    ├── 02_OpenSSL_eddsa_sign
    └── ...
```

### Configure + Build + Deploy

```bash
source /opt/st/stm32mp1/<ver>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi

cmake -B build/all \
      -DCMAKE_TOOLCHAIN_FILE=cmake/stm32mp1-toolchain.cmake \
      -DDEPLOY_TARGET=root@<board-ip>

cmake --build build/all
cmake --build build/all --target deploy
```

The single `deploy` target deploys both providers and all examples from their respective subdirectories.

---

## OpenSSL 3.x Provider Integration

The two provider modules expose secure element operations through the standard OpenSSL 3.x `EVP_*` API. Applications load them with `OSSL_PROVIDER_load()` and use them identically to any other OpenSSL provider.

### Provider summary

| Provider name | Module file | Device | Algorithms |
|---|---|---|---|
| `stsafea` | `stsafea.so` | STSAFE-A120 | `EC` keymgmt · `ECDSA` sign/verify (NIST P-256/384/521, Brainpool P-256/384/512) |
| `stsafel` | `stsafel.so` | STSAFE-L010 | `ED25519` keymgmt · `EdDSA` sign (HW) · `EdDSA` verify (SW) |

### Runtime setup

The `OPENSSL_MODULES` environment variable must point to the directory containing the provider `.so` files:

```bash
export OPENSSL_MODULES=/usr/lib/ossl-modules
```

Or set it permanently in `/etc/environment` or the systemd service environment.

### Custom parameters

Both providers accept custom OSSL_PARAM keys (defined in `providers/stse_provider.h`):

| Parameter | Type | Default | Description |
|---|---|---|---|
| `stse-slot` | `uint32` | `0` | Hardware key slot index |
| `stse-bus` | `uint32` | `1` | Linux I²C bus number (`/dev/i2c-N`) |

---

### Using the stsafea provider (STSAFE-A120, ECDSA)

```c
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "providers/stse_provider.h"   /* STSE_PROV_PARAM_SLOT, STSE_PROV_PARAM_BUS */

/* 1. Load providers */
OSSL_PROVIDER *prov_a = OSSL_PROVIDER_load(NULL, "stsafea");
OSSL_PROVIDER *prov_d = OSSL_PROVIDER_load(NULL, "default");  /* software fallback */

/* 2. Generate a NIST P-256 key pair on hardware slot 1, bus 1 */
uint32_t slot = 1, bus = 1;
OSSL_PARAM params[] = {
    OSSL_PARAM_construct_uint32(STSE_PROV_PARAM_SLOT, &slot),
    OSSL_PARAM_construct_uint32(STSE_PROV_PARAM_BUS,  &bus),
    OSSL_PARAM_construct_end()
};

EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=stsafea");
EVP_PKEY_keygen_init(kctx);
EVP_PKEY_CTX_set_params(kctx, params);
EVP_PKEY *hw_key = NULL;
EVP_PKEY_generate(kctx, &hw_key);
EVP_PKEY_CTX_free(kctx);

/* 3. Sign (hardware) */
EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();
EVP_DigestSignInit_ex(sign_ctx, NULL, "SHA2-256", NULL, "provider=stsafea", hw_key, NULL);
size_t sig_len = 0;
EVP_DigestSign(sign_ctx, NULL, &sig_len, data, data_len);   /* get size */
unsigned char *sig = OPENSSL_malloc(sig_len);
EVP_DigestSign(sign_ctx, sig, &sig_len, data, data_len);    /* sign */
EVP_MD_CTX_free(sign_ctx);

/* 4. Verify (hardware) */
EVP_MD_CTX *vfy_ctx = EVP_MD_CTX_new();
EVP_DigestVerifyInit_ex(vfy_ctx, NULL, "SHA2-256", NULL, "provider=stsafea", hw_key, NULL);
int ok = EVP_DigestVerify(vfy_ctx, sig, sig_len, data, data_len);   /* 1 = valid */
EVP_MD_CTX_free(vfy_ctx);

/* 5. Cleanup */
OPENSSL_free(sig);
EVP_PKEY_free(hw_key);
OSSL_PROVIDER_unload(prov_a);
OSSL_PROVIDER_unload(prov_d);
```

**Compile flags** (link only against OpenSSL — the provider is loaded at runtime):
```bash
${CC} my_app.c -o my_app -lssl -lcrypto -I path/to/providers
```

---

### Using the stsafel provider (STSAFE-L010, Ed25519)

> [!NOTE]
> The `default` provider **must** be loaded alongside `stsafel`; verification is internally delegated to it.

```c
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "providers/stse_provider.h"

/* 1. Load providers — both required */
OSSL_PROVIDER *prov_l = OSSL_PROVIDER_load(NULL, "stsafel");
OSSL_PROVIDER *prov_d = OSSL_PROVIDER_load(NULL, "default");

/* 2. Import public key from device certificate + configure slot/bus */
uint32_t slot = 0, bus = 1;
OSSL_PARAM params[] = {
    OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub_key_bytes, 32),
    OSSL_PARAM_construct_uint32(STSE_PROV_PARAM_SLOT, &slot),
    OSSL_PARAM_construct_uint32(STSE_PROV_PARAM_BUS,  &bus),
    OSSL_PARAM_construct_end()
};

EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", "provider=stsafel");
EVP_PKEY_fromdata_init(pctx);
EVP_PKEY *hw_key = NULL;
EVP_PKEY_fromdata(pctx, &hw_key, EVP_PKEY_PUBLIC_KEY, params);
EVP_PKEY_CTX_free(pctx);

/* 3. Sign (hardware — 16-byte challenge passed to device) */
EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();
EVP_DigestSignInit_ex(sign_ctx, NULL, NULL, NULL, "provider=stsafel", hw_key, NULL);
unsigned char sig[64];
size_t sig_len = sizeof(sig);
EVP_DigestSign(sign_ctx, sig, &sig_len, challenge_16bytes, 16);
EVP_MD_CTX_free(sign_ctx);

/* 4. Verify (software — delegated to default provider internally) */
EVP_MD_CTX *vfy_ctx = EVP_MD_CTX_new();
EVP_DigestVerifyInit_ex(vfy_ctx, NULL, NULL, NULL, NULL, hw_key, NULL);
int ok = EVP_DigestVerify(vfy_ctx, sig, sig_len, challenge_16bytes, 16);   /* 1 = valid */
EVP_MD_CTX_free(vfy_ctx);

/* 5. Cleanup */
EVP_PKEY_free(hw_key);
OSSL_PROVIDER_unload(prov_l);
OSSL_PROVIDER_unload(prov_d);
```

> [!IMPORTANT]
> **STSAFE-L010 sign input size**: The device signs a raw **16-byte challenge**. Do not pass pre-hashed data or arbitrary-length messages directly. The `02_OpenSSL_eddsa_sign` example demonstrates the complete flow including reading the device certificate and generating a random challenge.

---

## Troubleshooting

### `se-daemon` fails to start

**Symptom**: `systemctl status se-daemon` shows `Failed to open I²C bus`.

**Causes and fixes**:

1. **Wrong bus number** — Check which bus the device is on:
   ```bash
   ls /dev/i2c-*
   i2cdetect -y 1   # scan bus 1
   ```
   Update `--bus` in `/etc/systemd/system/se-daemon.service` and run `systemctl daemon-reload && systemctl restart se-daemon`.

2. **`i2c-dev` kernel module not loaded**:
   ```bash
   modprobe i2c-dev
   echo "i2c-dev" >> /etc/modules-load.d/i2c.conf
   ```

3. **`/dev/i2c-N` permissions** — `se-daemon` runs as root by default; if changed, add it to the `i2c` group:
   ```bash
   groupadd i2c
   usermod -aG i2c se-daemon
   ```

---

### `OSSL_PROVIDER_load()` returns NULL

**Symptom**: Application prints `OSSL_PROVIDER_load("stsafea") failed`.

**Fixes**:

1. **`OPENSSL_MODULES` not set or wrong path**:
   ```bash
   export OPENSSL_MODULES=/usr/lib/ossl-modules
   # Verify the .so is there:
   ls $OPENSSL_MODULES/stsafea.so
   ls $OPENSSL_MODULES/stsafel.so
   ```

2. **Provider not deployed** — Re-run the deploy target:
   ```bash
   cmake --build build/stsafe-a --target deploy
   ```

3. **OpenSSL version mismatch** — Provider compiled with OpenSSL 3.x headers must run against an OpenSSL 3.x runtime. Check:
   ```bash
   openssl version        # runtime
   pkg-config --modversion openssl   # build-time (on host/sysroot)
   ```

---

### `stse_init` returns an error code

**Symptom**: Example prints `stse_init ERROR : 0x....`

| Code | Meaning | Fix |
|---|---|---|
| `0x0001` | I²C bus open failed | Check bus number, `i2c-dev` module, `se-daemon` running |
| `0x0002` | Device not responding | Check I²C address, wiring; run `i2cdetect` |
| `0x0003` | Protocol error | Check device power; try power cycle |

**Common checks**:
```bash
# Is se-daemon running?
systemctl status se-daemon

# Is the socket accessible?
ls -la /var/run/se-daemon.sock

# Does your application user have permission?
# se-daemon socket uses UMask=0117 (group rw), group=root by default.
# Either run as root or add the user to the group that owns the socket.
```

---

### STSAFE-A120 key generation returns error `0x0011`

**Symptom**: `02_OpenSSL_ecdsa_sign_verify` prints `EC keygen ... err 17`.

**Cause**: Key slot 0 has an Access Condition restriction that prevents key generation without prior provisioning.

**Fix**: Use a different slot:
```bash
./02_OpenSSL_ecdsa_sign_verify 1 1   # bus=1, slot=1
```

To enable slot 0, run `02_Command_AC_provisioning` first or use the device's provisioning tool.

---

### Build error: `openssl/opensslconf.h: No such file or directory`

**Cause**: Cross-compilation without the SDK — the host's OpenSSL headers are being used instead of the cross-compiled sysroot's headers.

**Fix**: Always source the SDK environment before configuring:
```bash
source /opt/st/stm32mp1/<ver>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
```
Then delete the build directory and re-run `cmake -B build/...`.

---

### Build error: `STSELib submodule is not initialised`

```bash
git submodule update --init lib/STSELib
cd lib/STSELib && git checkout remotes/origin/feature/pkcs11 && cd -
```

---

### Provider loads but `EVP_PKEY_generate` fails silently

**Cause**: The property query string in the application doesn't match the provider name.

**Fix**: Ensure the property string exactly matches:
- `"provider=stsafea"` for STSAFE-A120 (EC / ECDSA operations)
- `"provider=stsafel"` for STSAFE-L010 (ED25519 operations)

Example:
```c
EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=stsafea");
```

---

### STSAFE-L010 sign returns error: `L010 requires strictly 16-byte challenge`

**Cause**: `EVP_DigestSign` was called with data larger than 16 bytes. STSAFE-L010 signs a raw 16-byte challenge (not a hash).

**Fix**: Pass exactly 16 bytes of data to `EVP_DigestSign`:
```c
unsigned char challenge[16];
RAND_bytes(challenge, sizeof(challenge));
EVP_DigestSign(ctx, sig, &sig_len, challenge, 16);
```

---

### `libstse.so` not found at runtime (`cannot open shared object file`)

**Cause**: The deployed `libstse.so` is not in the dynamic linker's search path.

**Fix**: The deploy target installs to `/usr/local/lib/` and runs `ldconfig`. If a custom prefix is used:
```bash
# On target
echo "/usr/local/lib" > /etc/ld.so.conf.d/stse.conf
ldconfig
```

Or set `LD_LIBRARY_PATH` temporarily (not recommended for production):
```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```
