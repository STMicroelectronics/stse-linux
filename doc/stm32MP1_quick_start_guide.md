# STM32MP1 Quick Start Guide

This guide walks you through setting up, cross-compiling, and deploying the **STSAFE Linux Middleware** and **OpenSSL 3.x Providers** onto an STM32MP1 target board running OpenSTLinux.

---

## 1. Prerequisites

### Host System Requirements (x86 Linux / Ubuntu)
Install basic host tools:
```bash
sudo apt update
sudo apt install -y cmake build-essential libssl-dev git openssh-client pkg-config
```

### OpenSTLinux Developer SDK
Download the OpenSTLinux SDK for your board from [st.com](https://www.st.com).

1. Make the installer executable and run it:
   ```bash
   chmod +x en.stm32mp1-openstlinux-<version>-developer-sdk.sh
   ./en.stm32mp1-openstlinux-<version>-developer-sdk.sh
   ```
2. Source the SDK environment script in every new terminal before running CMake:
   ```bash
   source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
   ```
   > [!IMPORTANT]
   > Sourcing this file exports the necessary cross-compilation environment variables (`CC`, `CXX`, `OECORE_TARGET_SYSROOT`, pkg-config paths).

---

## 2. Clone the Repository & Submodules

```bash
git clone https://github.com/STMicroelectronics/stse-linux.git
cd stse-linux
git submodule update --init lib/STSELib
cd lib/STSELib && git checkout remotes/origin/feature/pkcs11 && cd -
```

---

## 3. Configure, Build & Deploy

### A. Building for a Specific Device (e.g. STSAFE-A120)

```bash
# Ensure the OpenSTLinux SDK environment is sourced
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi

# Configure
cmake -B build/stm32mp1 \
      -DCMAKE_TOOLCHAIN_FILE=cmake/stm32mp1-toolchain.cmake \
      -DTARGET_DEVICE=STSAFE_A120 \
      -DDEPLOY_TARGET=root@<board-ip>

# Compile
cmake --build build/stm32mp1 -j$(nproc)

# Deploy to STM32MP1 over SSH
cmake --build build/stm32mp1 --target deploy
```

> [!TIP]
> Configure passwordless SSH with `ssh-copy-id root@<board-ip>` so the automated deployment step runs smoothly without asking for passwords.

### B. Building for All Devices

To build middleware and examples for all supported devices (`STSAFE_A120`, `STSAFE_A110`, `STSAFE_L010`):

```bash
cmake -B build/all \
      -DCMAKE_TOOLCHAIN_FILE=cmake/stm32mp1-toolchain.cmake \
      -DTARGET_DEVICE=ALL \
      -DDEPLOY_TARGET=root@<board-ip>

cmake --build build/all -j$(nproc)
cmake --build build/all --target deploy
```

---

## 4. What the `deploy` Target Does

When running `cmake --build <build_dir> --target deploy`, CMake executes an SSH/SCP sequence that:
1. Stops the `se-daemon` service on the target board.
2. Copies `se-daemon` to `/usr/local/sbin/se-daemon`.
3. Copies `libstse.so.1.0` to `/usr/local/lib/`, updates symlinks, and runs `ldconfig`.
4. Copies the provider module (`stsafe-*.so`) to the board's OpenSSL modules directory (auto-detected via `openssl version -a`).
5. Installs the example binaries into `/home/root/stse-linux/<device_name>/`.
6. Copies `se-daemon.service` to `/etc/systemd/system/`.
7. Reloads systemd and enables/starts `se-daemon`.

---

## 5. Running and Testing on STM32MP1

1. **SSH into the STM32MP1 board**:
   ```bash
   ssh root@<board-ip>
   ```

2. **Verify `se-daemon` status**:
   ```bash
   systemctl status se-daemon
   ls -la /var/run/se-daemon.sock
   ```

3. **Verify I²C connectivity**:
   ```bash
   i2cdetect -y 1
   ```
   - Address `0x20`: STSAFE-A110 / STSAFE-A120 detected
   - Address `0x0c`: STSAFE-L010 detected

4. **Run Example Binaries**:
   ```bash
   cd /home/root/stse-linux/stsafe-a120

   # Basic I²C loopback test
   ./01_Echo_loop

   # Device authentication test
   ./01_Device_authentication

   # Hardware-backed OpenSSL ECDSA sign and verify
   export OPENSSL_MODULES=/usr/lib/ossl-modules
   ./02_OpenSSL_ecdsa_sign_verify 1 1
   ```
