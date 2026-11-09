# STSE-LINUX MIDDLEWARE TRAINING MANUAL
## Secure Element Integration, Cross-Compilation, Custom Battery Management, & OpenSSL Provider

---

**Document Reference**: TM-STSE-LINUX-2026-V1.0  
**Target Secure Elements**: STSAFE-A110, STSAFE-A120, STSAFE-L010  
**Target MPU Platforms**: STM32MP1 (ARM Cortex-A7), Raspberry Pi (arm64 / armhf), Embedded Linux  
**Author**: CS Application & Security Engineering Team  

---

<div style="page-break-after: always;"></div>

# Front Page: Training Scope & Prerequisites

## Training Scope & Objectives

This comprehensive training curriculum is designed for embedded Linux software engineers, system architects, and IoT security practitioners integrating STMicroelectronics **STSAFE-A** and **STSAFE-L** Secure Elements into Linux/MPU-based products.

Participants will master the complete architecture and deployment lifecycle of the `stse-linux` middleware ecosystem:
1. **Architecture & Security Boundary**: Understand the privilege-separated daemon (`se-daemon`), the client IPC library (`libstse.so`), and runtime OpenSSL 3.x provider architecture.
2. **Assignment 1 — Environment & Cross-Compilation**: Configure cross-toolchain environments (OpenSTLinux SDK & Raspberry Pi), build `stse-linux`, deploy over SSH, run privilege-separated daemon services, and validate with cross-compiled target examples.
3. **Assignment 2 — Custom Application Development (Battery Management System on L010)**: Architect and build an industrial **Smart Battery Management System (BMS)** using the ultra-low-power **STSAFE-L010**. Learn how to configure User-NVM counter zones, implement secure decrementing discharge/cycle counters, log tamper-evident telemetry state buffers, and authenticate battery pack authenticity using Ed25519 digital signatures.
4. **Assignment 3 — OpenSSL 3.x Provider Integration via Linux CLI**: Configure OpenSSL 3.x to load STSAFE providers, generate hardware-backed keys, execute hardware ECDSA / EdDSA signing and verification, and issue certificates directly via standard Linux command-line utilities (`openssl genpkey`, `openssl req`, `openssl dgst`).

---

## Prerequisites Matrix

### Hardware Prerequisites

| Hardware Component | Specification | Purpose |
|:---|:---|:---|
| **Target MPU Board** | STM32MP157F-DK2 / STM32MP135F-DK or Raspberry Pi (3/4/5/CM4) | Host running Linux kernel ≥ 4.15 |
| **Secure Element Expansion** | X-NUCLEO-SAFEA1 (STSAFE-A120/A110) or X-NUCLEO-ESE02A1 (STSAFE-L010) or discrete DIP/SO8 module | Target Secure Element hardware |
| **I²C Interconnect** | Dedicated I²C bus (`/dev/i2c-1` or `/dev/i2c-2`), pull-up resistors (2.2kΩ–4.7kΩ to 3.3V) | Bus 1 default (Addr `0x20` for A110/A120, `0x0C` for L010) |
| **Debug Connection** | Micro-USB / USB-C ST-LINK cable or Ethernet / Wi-Fi network interface | Serial console (115200 8N1) and SSH communication |
| **Host PC** | Linux x86_64 workstation (Ubuntu 22.04 LTS / 24.04 LTS or Debian 12) | Cross-compilation and development host |

### Software Prerequisites

| Tool / Package | Required Version | Role |
|:---|:---|:---|
| **Build Tools** | CMake ≥ 3.18, Make / Ninja, GCC / Clang, Git, pkg-config | Core build system |
| **Host OpenSSL** | OpenSSL 3.0+ development headers (`libssl-dev`) | Provider interface compilation |
| **Target SDK (Mode A)** | OpenSTLinux Developer SDK (Cortex-A7 vfpv4-neon toolchain) | Cross-toolchain & target sysroot |
| **Target Toolchain (Mode B)** | `gcc-arm-linux-gnueabihf` (32-bit) or `gcc-aarch64-linux-gnu` (64-bit) | Generic cross-compilation |
| **Target Board OS** | OpenSTLinux (Dunfell/Kirkstone/Mickledore) or Raspberry Pi OS (Debian 11/12) | Linux OS with `systemd` and `i2c-dev` |
| **Network & Access** | OpenSSH client (`ssh`, `scp`), passwordless SSH key pair (`ssh-copy-id`) | Automated binary and library deployment |
| **Diagnostic Utilities** | `i2c-tools` (`i2cdetect`, `i2cget`, `i2cset`) | Bus verification on target |

---

<div style="page-break-after: always;"></div>

# 1. Introduction: `stse-linux` Middleware Description

## 1.1 Architectural Overview & Motivation

Embedded Linux platforms running complex user-space stacks face significant security challenges when interfacing with hardware cryptographic chips:
- Direct hardware access to `/dev/i2c-*` typically requires root privileges, violating the **Principle of Least Privilege**.
- Multiple concurrent processes (e.g., IoT edge daemons, web servers, update managers) accessing the same I²C peripheral can corrupt bus transactions, cause frame interleaving, and trigger hardware bus lockups.
- Standard cryptographic libraries (such as OpenSSL) require hardware drivers to conform to modern pluggable provider architectures rather than proprietary legacy APIs.

`stse-linux` addresses these challenges by introducing a modular, three-tier architecture:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               Application Space                                        │
│     Standard OpenSSL CLI / EVP Apps            Native STSELib C Applications           │
│   (e.g., openssl, nginx, custom bms)         (e.g., device auth, provisioning)         │
└───────────────────────────┬────────────────────────────────────┬───────────────────────┘
                            │                                    │
                            ▼                                    │
┌─────────────────────────────────────────────────────────┐      │
│                 OpenSSL 3.x Providers                   │      │
│  stsafe-a120.so  │  stsafe-a110.so  │  stsafe-l010.so   │      │
│  (ECDSA HW)      │  (ECDSA HW)      │  (Ed25519 Sign HW)│      │
└───────────────────────────┬─────────────────────────────┘      │
                            │                                    │
                            ▼                                    ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                       libstse.so                                       │
│    STSELib Cryptographic API + Linux IPC Platform Adaptation (stse_platform_ipc)       │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Unix Domain Socket
                                            │ /var/run/se-daemon.sock
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                      se-daemon                                         │
│               Root Privileged Bus Manager & Mutex-Protected Frame Proxy                │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Linux Kernel I2C Driver
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                    /dev/i2c-N                                          │
│           STSAFE-A110 (0x20)  │  STSAFE-A120 (0x20)  │  STSAFE-L010 (0x0C)             │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 1.2 Component Breakdown

### 1. `se-daemon` (Privileged I²C Bus Proxy)
- **Role**: Sits between untrusted user processes and the Linux kernel I²C subsystem (`/dev/i2c-N`).
- **Privilege Separation**: Runs as a `systemd` system service with root or `i2c` group privileges.
- **Serialization & Concurrency**: Manages multi-client transactions using Unix Domain Sockets (`/var/run/se-daemon.sock`). Every transaction (wake-up, send command, polling/wait, receive response, power-down) is atomically sequenced, guaranteeing zero bus collisions between concurrent processes.
- **Safety**: Isolates the raw kernel device nodes; unprivileged applications never need read/write access to `/dev/i2c-*`.

### 2. `libstse.so` (STSE Client Shared Library)
- **Core STSELib Engine**: Houses the complete STMicroelectronics STSE command encoders, decoders, access condition validators, and payload builders.
- **Platform IPC Layer (`STSELib_Platform`)**: Implements `stse_platform_i2c.c` over local socket IPC. When an application calls an STSE API (e.g. `stse_device_authenticate()`), the platform layer serializes the raw frame, dispatches it over `/var/run/se-daemon.sock`, and blocks until the daemon returns the SE response.
- **Universal Device Handler**: Exposes the `stse_Handler_t` structure, encapsulating device type, I²C bus ID, target address, session keys, and communication timeouts.

### 3. OpenSSL 3.x Cryptographic Providers
OpenSSL 3.x deprecated legacy "engines" in favor of the **Provider Architecture** (`OSSL_PROVIDER`). `stse-linux` implements three dedicated provider modules:
- **`stsafe-a120.so`**: Full hardware-backed NIST ECC (P-256, P-384, P-521), Brainpool (P-256, P-384, P-512), and Ed25519 key generation and ECDSA sign/verify.
- **`stsafe-a110.so`**: Hardware-backed NIST ECC (P-256, P-384) and Brainpool (P-256, P-384) key generation and ECDSA sign/verify.
- **`stsafe-l010.so`**: Hardware-backed Ed25519 digital signature generation using private keys permanently protected inside the L010 SE. Signature verification is automatically and transparently delegated to OpenSSL's built-in `default` provider.

---

## 1.3 Target Secure Element Comparison Matrix

The table below contrasts the technical characteristics of the supported secure elements:

| Feature / Metric | STSAFE-A110 | STSAFE-A120 | STSAFE-L010 |
|:---|:---|:---|:---|
| **Primary Focus** | Brand protection & authentication | High-performance IoT security & cloud connectivity | Ultra-low power, cost-sensitive peripherals & batteries |
| **I²C 7-bit Address** | `0x20` | `0x20` | `0x0C` |
| **Asymmetric Curves** | NIST P-256 / P-384<br>Brainpool P-256 / P-384 | NIST P-256 / 384 / 521<br>Brainpool P-256 / 384 / 512<br>Ed25519 / X25519 | Edwards Ed25519 only |
| **Hardware Operations** | ECDSA Sign & Verify<br>ECDH, RNG, SHA-256/384 | ECDSA Sign & Verify<br>ECDH, Symmetric AES-128/256 CCM/CMAC, RNG, SHA | Ed25519 Sign only<br>(Verify delegated to SW) |
| **User Non-Volatile Memory**| Configurable zones & monotonic counters | Configurable zones & monotonic counters | Fixed zones (e.g., Zone 32 counter + 16-byte buffer) |
| **Wake-up Protocol** | Standard wake-up sequence required | Standard wake-up sequence required | **Instant awake** (no wake-up sequence needed) |
| **Typical Target Use Cases**| Consumables, smart accessories, industrial controllers | Secure gateways, Linux MPUs, Matter/Thread nodes, TLS offloading | Battery packs, medical disposables, disposable sensors, Qi wireless chargers |

---

## 1.4 Cryptographic Fundamentals & PKI Architecture

### Public Key Cryptography & Key Isolation
Every STSAFE device contains at least one factory-provisioned asymmetric private key stored in tamper-proof non-volatile hardware memory:
- **Private Key Immutability**: Private keys can **never** be exported, read, or dumped across the I²C bus.
- **Hardware Cryptographic Execution**: Cryptographic operations requiring the private key (such as digital signing or key derivation) are executed internally by the secure element's hardware cryptographic coprocessor.
- **Public Key Distribution**: The matching public key is embedded within an X.509 device certificate or exported for validation.

### Certificate Hierarchy & Root of Trust (RoT)
To prevent counterfeit devices from injecting unauthorized public keys, devices are embedded in a Public Key Infrastructure (PKI):

```
       ┌────────────────────────────────────────────────────────┐
       │              STMicroelectronics Root CA                │
       │           (Self-Signed Trusted Certificate)            │
       └───────────────────────────┬────────────────────────────┘
                                   │ Signs
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │               Subordinate / Intermediate CA            │
       │              (SPL Personalization Profile)             │
       └───────────────────────────┬────────────────────────────┘
                                   │ Signs & Provisions at Factory
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │               STSAFE Device Leaf Certificate           │
       │           (Stored in Secure Element Zone 0)            │
       │   - Unique Serial Number                               │
       │   - Subject Public Key (Matches Protected Private Key) │
       │   - Digital Signature of Intermediate / Root CA        │
       └────────────────────────────────────────────────────────┘
```

### Challenge-Response Device Authentication Protocol
Authentication of a remote or local peripheral follows an unforgeable 4-phase sequence:
1. **Certificate Extraction**: The host requests the leaf certificate from the SE (Zone 0) via `stse_get_device_certificate()`.
2. **Path Validation**: The host verifies the leaf certificate against the known ST Root/Intermediate CA public key.
3. **Fresh Challenge Issuance**: The host generates a cryptographically secure random challenge (e.g., 16 or 32 random bytes) to prevent replay attacks.
4. **Hardware Signature & Verification**: The SE signs the challenge using its internal private key. The host validates this signature using the public key extracted from the verified certificate.

---

<div style="page-break-after: always;"></div>

# 2. Assignment 1: Setup the Environment & Run Cross-Compiled Examples

## 2.1 Assignment Objectives
- Configure an x86 Linux development workstation with cross-compilation toolchains.
- Clone and initialize `stse-linux` and the `STSELib` git submodule.
- Cross-compile `stse-linux` for the target platform (STM32MP1 Cortex-A7 or Raspberry Pi).
- Deploy the daemon, shared libraries, and example suite over SSH using CMake target automations.
- Start and verify `se-daemon` as an active `systemd` service.
- Execute and analyze target cross-compiled verification binaries (`01_Echo_loop` and `01_Device_authentication`).

---

## 2.2 Host Environment Setup & Toolchains

### Step 1: Install Workstation Dependencies
On your Ubuntu/Debian development host, install all required build utilities:

```bash
sudo apt update
sudo apt install -y cmake build-essential gcc g++ git libssl-dev pkg-config openssh-client tar
```

### Step 2: Configure Cross-Toolchain

#### Option A: OpenSTLinux Developer SDK (STM32MP1 Targets — Recommended)
Download and install the official OpenSTLinux SDK:
```bash
chmod +x en.stm32mp1-openstlinux-*.sh
./en.stm32mp1-openstlinux-*.sh -d /opt/st/stm32mp1/sdk
```

Before compiling in any terminal session, initialize the SDK cross-environment:
```bash
source /opt/st/stm32mp1/sdk/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
```
*Verification*: Check that `$CC` points to `arm-ostl-linux-gnueabi-gcc`.

#### Option B: Raspberry Pi Cross-Toolchain (Ubuntu Host)
For 64-bit Raspberry Pi OS (`aarch64` / Pi 3, 4, 5, Zero 2W):
```bash
sudo apt install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
```
For 32-bit Raspberry Pi OS (`armhf`):
```bash
sudo apt install -y gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
```

---

## 2.3 Repository Preparation & Submodule Checkout

Clone the `stse-linux` middleware repository and check out the required `STSELib` branch:

```bash
git clone https://github.com/STMicroelectronics/stse-linux.git
cd stse-linux

# Initialize and update the core STSELib submodule
git submodule update --init lib/STSELib
cd lib/STSELib
git checkout remotes/origin/feature/pkcs11
cd ../..
```

---

## 2.4 Configuring & Building the Middleware

Set up passwordless SSH authentication to your target board (e.g. `192.168.1.120`):
```bash
ssh-copy-id root@192.168.1.120
```

### Configure CMake for STSAFE-A120:
```bash
cmake -B build/stsafe-a120 \
      -DCMAKE_TOOLCHAIN_FILE=cmake/stm32mp1-toolchain.cmake \
      -DTARGET_DEVICE=STSAFE_A120 \
      -DDEPLOY_TARGET=root@192.168.1.120 \
      -DDEPLOY_EXAMPLES_DIR=/home/root/stse-linux
```

*(For Raspberry Pi, substitute `-DCMAKE_TOOLCHAIN_FILE=cmake/rpi-toolchain.cmake -DRPI_ARCH=arm64 -DDEPLOY_TARGET=pi@raspberrypi.local`)*

### Compile the Binaries:
```bash
cmake --build build/stsafe-a120 -j$(nproc)
```

The build generates:
- `build/stsafe-a120/se-daemon` (The I²C proxy daemon)
- `build/stsafe-a120/libstse.so` (The client library)
- `build/stsafe-a120/stsafe-a120.so` (OpenSSL 3.x Provider module)
- `build/stsafe-a120/01_Echo_loop`, `01_Device_authentication`, etc. (Verification binaries)

---

## 2.5 Automated SSH Deployment & Service Activation

Deploy all artifacts directly to the target board in one command:
```bash
cmake --build build/stsafe-a120 --target deploy
```

What the `deploy` target performs automatically over SSH:
1. Stops any existing `se-daemon` process on the target board.
2. Copies `se-daemon` to `/usr/local/sbin/se-daemon`.
3. Copies `libstse.so` to `/usr/local/lib/` and runs `ldconfig`.
4. Copies `stsafe-a120.so` into the target's OpenSSL modules directory (`/usr/lib/ossl-modules`).
5. Uploads all example binaries into `/home/root/stse-linux/stsafe-a120/`.
6. Installs and starts `/etc/systemd/system/se-daemon.service`.

---

## 2.6 Target Execution & Step-by-Step Verification

Log in to the target MPU board:
```bash
ssh root@192.168.1.120
```

### Step 1: Confirm Hardware I²C Bus Detection
Scan I²C Bus 1 to ensure the secure element responds at address `0x20` (or `0x0C` for L010):
```bash
i2cdetect -y 1
```
Output:
```
     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
00:                         -- -- -- -- -- -- -- -- 
10: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- 
20: 20 -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- 
...
```

### Step 2: Verify `se-daemon` Status
```bash
systemctl status se-daemon
ls -la /var/run/se-daemon.sock
```
Ensure the socket file exists and is active.

### Step 3: Run the Low-Level Echo Loop Test
```bash
cd /home/root/stse-linux/stsafe-a120
./01_Echo_loop 1
```
*Expected Terminal Output*:
```
----------------------------------------------------------------------------------------------------------------
-                                    STSAFE-A120 Echo loop example                                             -
----------------------------------------------------------------------------------------------------------------
 - Initialize target STSAFE-A120 on /dev/i2c-1
 ## Message :
  0xA4 0x1B 0x78 0x3E 0x90 0xF2
 ## Echoed Message :
  0xA4 0x1B 0x78 0x3E 0x90 0xF2
*#*# STMICROELECTRONICS #*#*
```

### Step 4: Run Hardware Certificate & Chain Authentication
```bash
./01_Device_authentication 1
```
*Expected Terminal Output*:
```
----------------------------------------------------------------------------------------------------------------
-                                STSAFE-A120 Device Authentication Example                                     -
----------------------------------------------------------------------------------------------------------------
 - Initialize target STSAFE-A120 on /dev/i2c-1
 ## Device authentication over ST SPL02 CA certificate : Successful
```

---

<div style="page-break-after: always;"></div>

# 3. Assignment 2: Create Your Own Example — Battery Management System on STSAFE-L010

## 3.1 Industrial Use Case: Smart Battery Pack Security

In modern mission-critical portable equipment (e.g., medical infusion pumps, industrial power tools, defense communication gear, e-mobility), counterfeit or degraded lithium-ion battery packs introduce major fire hazards, system instability, and liability risks.

A resilient Battery Management System (BMS) requires hardware-enforced protection:
1. **Counterfeit Prevention**: Cryptographic proof of battery pack authenticity via digital signatures.
2. **Guaranteed Cycle Life Tracking**: A decrement-only hardware counter tracking discharge cycles that cannot be reset or rolled back by malicious software or cloned EEPROMs.
3. **Telemetry & Health Logging**: Tamper-evident non-volatile storage preserving battery health metrics (State of Charge, Health %, Over-temperature events).

The **STSAFE-L010** is the ideal secure element for this application:
- Operates on ultra-low power budget.
- Features I²C address `0x0C` with instant wake-up.
- Provides User-NVM Zone 32 with a coupled 24-bit decrement counter and 16-byte state buffer.
- Features hardware Ed25519 digital signature generation.

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                               Target Linux Host                                  │
│                 BMS Service / Battery Daemon (User Application)                  │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │ libstse.so IPC
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                           STSAFE-L010 Secure Element                             │
│                                                                                  │
│  ┌─────────────────────────┐                 ┌────────────────────────────────┐  │
│  │   Zone 0: Certificate   │                 │   Zone 32: Decrement Counter   │  │
│  │   - Ed25519 Public Key  │                 │   - 24-bit Hardware Counter    │  │
│  │   - Factory CA Signed   │                 │   - 16-byte Telemetry Buffer   │  │
│  └─────────────────────────┘                 └────────────────────────────────┘  │
│  ┌─────────────────────────┐                                                     │
│  │   Slot 0: Private Key   │ ──► Ed25519 Hardware Signature Core                 │
│  │   - Factory Provisioned │     (Authenticates battery to host charger)         │
│  └─────────────────────────┘                                                     │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3.2 BMS Application Architecture & Data Structures

We define a 16-byte telemetry record stored directly in STSAFE-L010 Zone 32:

```c
#pragma pack(push, 1)
typedef struct {
    uint16_t pack_voltage_mv;   /* Battery pack terminal voltage in mV   */
    int16_t  current_ma;        /* Instantaneous current in mA           */
    int8_t   temperature_c;     /* Internal pack temperature in deg C    */
    uint8_t  state_of_charge;   /* Fuel gauge percentage (0 - 100%)      */
    uint8_t  state_of_health;   /* Health index percentage (0 - 100%)    */
    uint8_t  fault_flags;       /* Bitmask: 0x01: OverTemp, 0x02: OverVolt*/
    uint8_t  reserved[8];       /* Reserved for future expansion         */
} bms_telemetry_payload_t;      /* Exactly 16 bytes                      */
#pragma pack(pop)
```

### STSELib APIs Employed:
- `stse_set_default_handler_value()` & `stse_init()`: Device session initialization.
- `stse_data_storage_read_counter_zone()`: Atomically read current counter & 16-byte telemetry payload.
- `stse_data_storage_decrement_counter_zone()`: Atomically decrement counter by $N$ units and write updated 16-byte telemetry payload.
- `stse_device_authenticate()`: Perform challenge-response Ed25519 authentication against the ST production root certificate.

---

## 3.3 Complete Implementation: `bms_l010_example.c`

Create a new directory in your `stse-linux` tree: `examples/stsafe-l010/03_Battery_management_system/` and add `main.c`:

```c
/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-L010 Battery Management System (BMS) Example
 *          Demonstrates tamper-evident battery cycle tracking and authentication.
 ******************************************************************************
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "Apps_utils.h"

/* Root CA key for STSAFE-L SPL01 profile */
#define CA_SELF_SIGNED_CERTIFICATE_01                                                                   \
    0x30, 0x82, 0x01, 0x67, 0x30, 0x82, 0x01, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01,     \
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x4b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, \
    0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, \
    0x15, 0x53, 0x54, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x6e, \
    0x69, 0x63, 0x73, 0x20, 0x6e, 0x76, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, \
    0x13, 0x53, 0x54, 0x4d, 0x5f, 0x53, 0x54, 0x53, 0x41, 0x46, 0x45, 0x2d, 0x4c, 0x5f, 0x43, 0x41, \
    0x30, 0x30, 0x30, 0x31, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x34, 0x30, 0x36, 0x30, 0x37, 0x30, 0x30, \
    0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x35, 0x34, 0x30, 0x36, 0x30, 0x37, 0x30, \
    0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x4b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, \
    0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x15, \
    0x53, 0x54, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x6e, 0x69, \
    0x63, 0x73, 0x20, 0x6e, 0x76, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, \
    0x53, 0x54, 0x4d, 0x5f, 0x53, 0x54, 0x53, 0x41, 0x46, 0x45, 0x2d, 0x4c, 0x5f, 0x43, 0x41, 0x30, \
    0x30, 0x30, 0x31, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x84, \
    0x47, 0xf2, 0xc0, 0x98, 0xbe, 0x15, 0xf6, 0x05, 0xc6, 0x98, 0xd5, 0xfa, 0xc5, 0x7b, 0x56, 0x0f, \
    0x1c, 0xcf, 0x1f, 0x37, 0x9f, 0xe9, 0x88, 0xaa, 0x2f, 0xea, 0xa2, 0x93, 0xb5, 0xde, 0xd1, 0xa3, \
    0x20, 0x30, 0x1e, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, \
    0xff, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x02, \
    0x04, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00, 0x29, 0x31, 0xa8, 0x6f, 0xed, \
    0x6f, 0xd7, 0x54, 0x8a, 0x03, 0x20, 0x72, 0x84, 0x5d, 0x77, 0x87, 0x97, 0xe2, 0x36, 0x4b, 0x52, \
    0x65, 0xea, 0xc1, 0xbf, 0x7b, 0x39, 0x36, 0x05, 0x75, 0x5b, 0x5d, 0x76, 0x19, 0xfd, 0x32, 0x9c, \
    0xfd, 0x90, 0x93, 0x17, 0xf9, 0x53, 0xb4, 0xb8, 0x21, 0xdf, 0x9c, 0xe2, 0x0d, 0xa7, 0xcd, 0x74, \
    0x5b, 0x9e, 0xf1, 0xab, 0xf7, 0x94, 0x9f, 0x4a, 0xb0, 0xfb, 0x05

#define BMS_ZONE_INDEX              32U
#define BMS_CERTIFICATE_ZONE        0U
#define BMS_PRIVATE_KEY_SLOT        0U
#define INITIAL_LIFETIME_CYCLES     1000U

#pragma pack(push, 1)
typedef struct {
    uint16_t pack_voltage_mv;   /* Battery pack voltage (mV)             */
    int16_t  current_ma;        /* Instantaneous current (mA)            */
    int8_t   temperature_c;     /* Temperature (°C)                      */
    uint8_t  state_of_charge;   /* SOC (0 - 100%)                        */
    uint8_t  state_of_health;   /* SOH (0 - 100%)                        */
    uint8_t  fault_flags;       /* Fault flags bitmask                   */
    uint8_t  reserved[8];       /* Reserved alignment padding            */
} bms_telemetry_t;
#pragma pack(pop)

int main(int argc, char *argv[])
{
    stse_ReturnCode_t ret;
    stse_Handler_t stse_handler;
    uint8_t bus_id = 1;
    uint32_t remaining_cycles = 0;
    bms_telemetry_t telemetry_in, telemetry_out;
    static const uint8_t ca_cert[] = {CA_SELF_SIGNED_CERTIFICATE_01};

    if (argc > 1) {
        bus_id = (uint8_t)atoi(argv[1]);
    }

    apps_terminal_init(115200);
    printf("====================================================================\n");
    printf("   STSAFE-L010 INDUSTRIAL SMART BATTERY MANAGEMENT SYSTEM (BMS)    \n");
    printf("====================================================================\n\n");

    /* 1. Initialize STSE Device Handler */
    ret = stse_set_default_handler_value(&stse_handler);
    if (ret != STSE_OK) {
        printf("Error: stse_set_default_handler_value (0x%04X)\n", ret);
        return EXIT_FAILURE;
    }

    stse_handler.device_type = STSAFE_L010;
    stse_handler.io.busID    = bus_id;
    stse_handler.io.BusSpeed = 100;
    stse_handler.io.Devaddr  = 0x0C;

    printf("[1] Connecting to STSAFE-L010 on I2C bus /dev/i2c-%u (Addr 0x0C)...\n", bus_id);
    ret = stse_init(&stse_handler);
    if (ret != STSE_OK) {
        printf("Error: stse_init failed with code 0x%04X\n", ret);
        return EXIT_FAILURE;
    }
    printf("    -> STSAFE-L010 connected and verified.\n\n");

    /* 2. Cryptographic Authenticity Verification */
    printf("[2] Verifying Battery Pack Authenticity (ST PKI Chain & Ed25519 Auth)...\n");
    ret = stse_device_authenticate(&stse_handler,
                                   ca_cert,
                                   BMS_CERTIFICATE_ZONE,
                                   BMS_PRIVATE_KEY_SLOT);
    if (ret != STSE_OK) {
        printf(PRINT_RED "    AUTHENTICATION FAILED: Non-genuine battery pack detected!\n" PRINT_RESET);
        printf("    Refusing to charge or discharge unverified pack.\n");
        return EXIT_FAILURE;
    }
    printf(PRINT_GREEN "    AUTHENTICATION SUCCESS: Genuine OEM battery pack confirmed.\n\n" PRINT_RESET);

    /* 3. Read Current Telemetry & Remaining Battery Cycles */
    printf("[3] Reading Current Pack Diagnostics from User-NVM Zone %u...\n", BMS_ZONE_INDEX);
    ret = stse_data_storage_read_counter_zone(&stse_handler,
                                              BMS_ZONE_INDEX,
                                              0x0000,
                                              (uint8_t *)&telemetry_in,
                                              sizeof(telemetry_in),
                                              04,
                                              &remaining_cycles,
                                              STSE_NO_PROT);
    if (ret != STSE_OK) {
        printf("Error reading zone %u (code 0x%04X)\n", BMS_ZONE_INDEX, ret);
        return EXIT_FAILURE;
    }

    printf("    -> Remaining Hardware Cycles : %u\n", remaining_cycles);
    printf("    -> Stored Voltage             : %u mV\n", telemetry_in.pack_voltage_mv);
    printf("    -> Stored Current             : %d mA\n", telemetry_in.current_ma);
    printf("    -> Stored Temperature         : %d deg C\n", telemetry_in.temperature_c);
    printf("    -> Stored State of Charge     : %u %%\n", telemetry_in.state_of_charge);
    printf("    -> Stored State of Health     : %u %%\n\n", telemetry_in.state_of_health);

    if (remaining_cycles == 0) {
        printf(PRINT_RED "CRITICAL: Battery cycle lifetime expired. Pack must be decommissioned.\n" PRINT_RESET);
        return EXIT_FAILURE;
    }

    /* 4. Simulate a Discharge/Charge Cycle and Update Diagnostics */
    printf("[4] Logging New Discharge Cycle & Updating Telemetry Record...\n");
    memset(&telemetry_out, 0, sizeof(telemetry_out));
    telemetry_out.pack_voltage_mv = 14400; /* 14.4 V */
    telemetry_out.current_ma      = -2200; /* 2.2 A discharge */
    telemetry_out.temperature_c   = 32;    /* 32 °C */
    telemetry_out.state_of_charge = 85;    /* 85 % */
    telemetry_out.state_of_health = 98;    /* 98 % */
    telemetry_out.fault_flags     = 0x00;  /* No faults */

    /* Decrement counter by 1 unit and atomically commit new telemetry */
    ret = stse_data_storage_decrement_counter_zone(&stse_handler,
                                                   BMS_ZONE_INDEX,
                                                   1,               /* Decrement amount */
                                                   0x0000,          /* Offset */
                                                   (uint8_t *)&telemetry_out,
                                                   sizeof(telemetry_out),
                                                   &remaining_cycles,
                                                   STSE_NO_PROT);
    if (ret != STSE_OK) {
        printf("Error updating decrement counter zone: 0x%04X\n", ret);
        return EXIT_FAILURE;
    }
    printf(PRINT_GREEN "    -> Hardware Counter Decremented Successfully!\n" PRINT_RESET);
    printf("    -> New Remaining Life Cycles: %u\n\n", remaining_cycles);

    /* 5. Readback Verification */
    printf("[5] Performing Readback Verification of NVM Zone %u...\n", BMS_ZONE_INDEX);
    memset(&telemetry_in, 0, sizeof(telemetry_in));
    ret = stse_data_storage_read_counter_zone(&stse_handler,
                                              BMS_ZONE_INDEX,
                                              0x0000,
                                              (uint8_t *)&telemetry_in,
                                              sizeof(telemetry_in),
                                              04,
                                              &remaining_cycles,
                                              STSE_NO_PROT);
    if (ret != STSE_OK) {
        printf("Error verifying zone %u: 0x%04X\n", BMS_ZONE_INDEX, ret);
        return EXIT_FAILURE;
    }

    if (memcmp(&telemetry_in, &telemetry_out, sizeof(bms_telemetry_t)) == 0) {
        printf(PRINT_GREEN "    -> VERIFICATION MATCH: Telemetry payload accurately recorded in hardware NVM.\n\n" PRINT_RESET);
    } else {
        printf(PRINT_RED "    -> VERIFICATION ERROR: NVM payload mismatch!\n\n" PRINT_RESET);
        return EXIT_FAILURE;
    }

    printf("====================================================================\n");
    printf("   BMS DEMO EXECUTION COMPLETE: SAFE & SECURE OPERATION CONFIRMED   \n");
    printf("====================================================================\n");
    return EXIT_SUCCESS;
}
```

---

## 3.4 CMake Build Integration & Testing

### Integrating into `CMakeLists.txt`
In the root `CMakeLists.txt`, register the new BMS example inside the `TARGET_DEVICE STSAFE_L010` block:

```cmake
stse_add_example(
    NAME "03_Battery_management_system"
    DEVICE "stsafe-l010"
    SOURCES "examples/stsafe-l010/03_Battery_management_system/main.c"
    INCLUDE_DIRS "examples/stsafe-l010/apps_utils"
    LINK_LIBS apps_utils_l010 stse
)
```

### Build & Deploy:
```bash
cmake --build build/stsafe-l010 --target deploy
```

### Execution on Target:
```bash
/home/root/stse-linux/stsafe-l010/03_Battery_management_system 1
```

---

<div style="page-break-after: always;"></div>

# 4. Assignment 3: Use OpenSSL Provider Through Linux Command Line

## 4.1 Architecture: How OpenSSL 3.x Dispatches to `stse-linux`

In OpenSSL 3.x, cryptographic algorithms are dynamically discovered at runtime through **Providers**. Instead of compiling code against proprietary vendor headers, standard user-space applications (such as curl, web servers, VPN daemons, or the standard `openssl` command-line utility) load `stsafe-a120.so`, `stsafe-a110.so`, or `stsafe-l010.so`.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        Linux Command Line Interface: `openssl`                         │
│             `openssl genpkey`  │  `openssl req`  │  `openssl dgst -sign`               │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Loads via -provider or config
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               OpenSSL 3.x Core Dispatch                                │
│       Finds matching algorithm by Property Query (e.g. "?provider=stsafe-a120")         │
├───────────────────────────────────────────┬────────────────────────────────────────────┤
│           STSAFE OpenSSL Provider         │             Default Provider               │
│               stsafe-a120.so              │                default.so                  │
│       - EC Keymgmt (NIST & BP curves)     │       - Standard Software Crypto           │
│       - Hardware ECDSA Sign               │       - ASN.1 Parsing, Formatting          │
│       - Hardware ECDSA Verify             │       - Software Fallback Verification     │
└───────────────────────────────────────────┴────────────────────────────────────────────┘
```

---

## 4.2 Configuring OpenSSL via Environment & Configuration Files

### Method 1: CLI Flags via Environment (`OPENSSL_MODULES`)
Set the environment variable pointing to the provider directory:
```bash
export OPENSSL_MODULES=/usr/lib/ossl-modules
```

Query and confirm that the provider is recognized by OpenSSL:
```bash
openssl list -providers -provider-path /usr/lib/ossl-modules -provider stsafe-a120 -provider default
```

*Expected Output*:
```
Providers:
  default
    name: OpenSSL Default Provider
    version: 3.0.22
    status: active
  stsafe-a120
    name: stsafe-a120
    version: 1.0.0
    status: active
```

---

### Method 2: System-Wide Configuration File (`/etc/ssl/openssl_stsafe.cnf`)
To enable hardware crypto without specifying `-provider` on every command line, create a custom configuration:

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
stsafe_a120 = stsafe_sect

[default_sect]
activate = 1

[stsafe_sect]
activate = 1
module = /usr/lib/ossl-modules/stsafe-a120.so
```

Activate it in your session:
```bash
export OPENSSL_CONF=/etc/ssl/openssl_stsafe.cnf
```

---

## 4.3 Practical CLI Scenarios

### Scenario A: Generate Hardware-Backed NIST P-256 Key Pair

Generate a private key securely inside **Key Slot 1** of the STSAFE-A120 (Slot 0 is often reserved with Access Conditions):

```bash
openssl genpkey \
    -provider-path /usr/lib/ossl-modules \
    -provider stsafe-a120 \
    -provider default \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:prime256v1 \
    -pkeyopt stse-slot:1 \
    -pkeyopt stse-bus:1 \
    -out stsafe_key.pem
```

#### Supported Elliptic Curves Reference (`-pkeyopt ec_paramgen_curve:<curve>`)

The OpenSSL provider maps standard curve identifiers to the underlying hardware cryptographic accelerator. The table below lists all supported curve names and aliases:

| Curve Family | Option (`-pkeyopt ec_paramgen_curve:...`) | Alias / Standard Name | Curve Size | Security Level | Supported Devices |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **NIST P-256** | `prime256v1` *(default)* | `P-256` | 256 bits | 128-bit | STSAFE-A110, STSAFE-A120 |
| **NIST P-384** | `secp384r1` | `P-384` | 384 bits | 192-bit | STSAFE-A110, STSAFE-A120 |
| **NIST P-521** | `nistp521` | `P-521` | 521 bits | 256-bit | STSAFE-A120 only |
| **Brainpool P-256** | `brainpoolP256r1` | — | 256 bits | 128-bit | STSAFE-A110, STSAFE-A120 |
| **Brainpool P-384** | `brainpoolP384r1` | — | 384 bits | 192-bit | STSAFE-A110, STSAFE-A120 |
| **Brainpool P-512** | `brainpoolP512r1` | — | 512 bits | 256-bit | STSAFE-A120 only |

> [!TIP]
> **Key Slot & Curve Compatibility**: Ensure the target slot in the STSAFE key table is provisioned or configured to accept the chosen curve size (e.g. 521-bit keys require appropriately sized slot allocation in the personalization profile).
>
> **X25519 Support (STSAFE-A120)**: For Diffie-Hellman key exchange over Curve25519, use `-algorithm X25519` instead of `-algorithm EC`:
> ```bash
> openssl genpkey -provider-path /usr/lib/ossl-modules -provider stsafe-a120 -provider default \
>     -algorithm X25519 -pkeyopt stse-slot:2 -pkeyopt stse-bus:1 -out stsafe_x25519.pem
> ```

Inspect the generated public key structure:
```bash
openssl pkey -in stsafe_key.pem -text -noout
```

---

### Scenario B: Create a Self-Signed X.509 Certificate Using Hardware Key

Generate an X.509 device identity certificate signed directly by the hardware secure element:

```bash
openssl req -new -x509 \
    -provider-path /usr/lib/ossl-modules \
    -provider stsafe-a120 \
    -provider default \
    -key stsafe_key.pem \
    -out device_cert.pem \
    -days 365 \
    -subj "/C=FR/O=STMicroelectronics/OU=Embedded Security/CN=STSAFE-A120 Device 001"
```

Verify certificate fields:
```bash
openssl x509 -in device_cert.pem -text -noout
```

---

### Scenario C: Sign a Payload in Hardware & Verify via OpenSSL

#### 1. Create a Sample Data Payload
```bash
echo "FIRMWARE_PAYLOAD_V2.1.0_AUTHENTICATED_BY_STSAFE" > payload.bin
```

#### 2. Execute Hardware Digital Signature
Sign the payload using SHA2-256 and the private key isolated inside the secure element:
```bash
openssl dgst -sha256 -sign stsafe_key.pem \
    -provider-path /usr/lib/ossl-modules \
    -provider stsafe-a120 \
    -provider default \
    -out payload.sig \
    payload.bin
```

#### 3. Extract the Public Key
```bash
openssl pkey -in stsafe_key.pem -pubout -out pubkey.pem
```

#### 4. Verify the Signature
Verify the signature against the extracted public key using standard software verification:
```bash
openssl dgst -sha256 -verify pubkey.pem \
    -signature payload.sig \
    payload.bin
```
*Expected Output*:
```
Verified OK
```

---

<div style="page-break-after: always;"></div>

# 5. Appendix & Troubleshooting Guide

## 5.1 Common Error Codes & Resolutions

| Error Code / Symptom | Root Cause | Solution |
|:---|:---|:---|
| `stse_init ERROR: 0x0001` | I²C device node could not be opened | Verify `i2c-dev` kernel module is loaded (`modprobe i2c-dev`) and `/dev/i2c-1` exists. Ensure `se-daemon` is running. |
| `stse_init ERROR: 0x0002` | Device unresponsive / I²C NACK | Confirm wiring, I²C pull-up resistors (3.3V), and run `i2cdetect -y <bus>`. Ensure target address is `0x20` (A110/A120) or `0x0C` (L010). |
| `0x0011` on Keygen | Access Condition restriction on Slot 0 | Key slot 0 is restricted by default personalization profile. Specify key slot 1 (`-pkeyopt stse-slot:1`). |
| `OSSL_PROVIDER_load() failed` | Provider module not found in search path | Export `OPENSSL_MODULES=/usr/lib/ossl-modules` or pass `-provider-path`. |
| `Failed to connect to se-daemon socket` | Permissions or daemon inactive | Check `systemctl status se-daemon`. Ensure your user belongs to the `i2c` or `root` group. |
| `L010 requires strictly 16-byte challenge` | Invalid challenge buffer size | STSAFE-L010 hardware signature engine strictly accepts 16 raw bytes; do not pass arbitrary hashed data directly. |

---

## 5.2 Verification Checklist

- [ ] I²C bus verified using `i2cdetect` (`0x20` or `0x0C`).
- [ ] `se-daemon` active and running under `systemctl`.
- [ ] Unix domain socket `/var/run/se-daemon.sock` accessible.
- [ ] Verification example `01_Echo_loop` succeeds.
- [ ] Verification example `01_Device_authentication` passes PKI validation.
- [ ] Custom BMS example executes cycle decrements and telemetry logging.
- [ ] OpenSSL providers loaded and confirmed with `openssl list -providers`.
- [ ] Command-line signature creation and verification succeeds with `Verified OK`.
