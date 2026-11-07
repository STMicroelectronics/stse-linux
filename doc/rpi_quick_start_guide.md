# Raspberry Pi Quick Start Guide

This guide details how to wire, build, and deploy the **STSAFE Linux Middleware** and **OpenSSL 3.x Providers** on Raspberry Pi (Pi 2, 3, 4, 5, Zero, Zero 2 W) running Raspberry Pi OS (Debian Bullseye / Bookworm).

---

## 1. Hardware Connection (40-Pin Header)

Connect your STSAFE evaluation board or chip to the Raspberry Pi 40-pin GPIO header:

| STSAFE Pin | Raspberry Pi Pin | Header Function | Description |
|---|---|---|---|
| **VCC** | Pin 1 (3.3V) or Pin 2 (5V) | 3V3 / 5V Power | Power supply |
| **GND** | Pin 6, 9, 14, 20, 25, 30, 34, 39 | Ground | System ground |
| **SDA** | Pin 3 | GPIO 2 (SDA) | I²C Data line (`/dev/i2c-1`) |
| **SCL** | Pin 5 | GPIO 3 (SCL) | I²C Clock line (`/dev/i2c-1`) |
| **RST** *(optional)* | Pin 11 (GPIO 17) | GPIO | Optional reset pin |

### Enable I²C Interface on Raspberry Pi OS
Enable I²C using `raspi-config`:
```bash
sudo raspi-config nonint do_i2c 0
```
Verify device connectivity on bus 1:
```bash
sudo apt update && sudo apt install -y i2c-tools
i2cdetect -y 1
```
Expected output:
- `0x20` present: STSAFE-A110 or STSAFE-A120
- `0x0c` present: STSAFE-L010

---

## 2. Option A: Native Compilation on Raspberry Pi (Recommended)

Since Raspberry Pi OS provides modern compilers and CMake, building directly on the board is the fastest and most convenient approach.

### Step 1: Install Dependencies
```bash
sudo apt update
sudo apt install -y cmake build-essential libssl-dev git i2c-tools pkg-config
# Optional (for GTK demo):
sudo apt install -y libgtk-3-dev
```

### Step 2: Clone the Repository & Submodules
```bash
git clone https://github.com/STMicroelectronics/stse-linux.git
cd stse-linux
git submodule update --init lib/STSELib
cd lib/STSELib && git checkout remotes/origin/feature/pkcs11 && cd -
```

### Step 3: Configure and Build
```bash
# Example: Build for STSAFE-A110 (or STSAFE_A120, STSAFE_L010, ALL)
cmake -B build -DTARGET_DEVICE=STSAFE_A110
cmake --build build -j$(nproc)
```

### Step 4: Install and Start Services Locally
```bash
# Install binaries and shared libraries to system paths
sudo cmake --install build

# Install and start the se-daemon service
sudo cp daemon/se-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now se-daemon

# Verify daemon status
systemctl status se-daemon
```

---

## 3. Option B: Cross-Compilation from Host PC & SSH Deploy

If you prefer building on an x86 Linux machine and deploying over SSH:

### Step 1: Install Cross-Compiler on Host
```bash
# For 64-bit Raspberry Pi OS (Pi 3/4/5, Zero 2W - arm64):
sudo apt install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

# For 32-bit Raspberry Pi OS (Pi 2/3/4, Zero - armhf):
sudo apt install -y gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
```

### Step 2: Configure Passwordless SSH
```bash
ssh-copy-id pi@raspberrypi.local
```

### Step 3: Build & Deploy
For 64-bit (`arm64`):
```bash
cmake -B build/rpi \
      -DCMAKE_TOOLCHAIN_FILE=cmake/rpi-toolchain.cmake \
      -DRPI_ARCH=arm64 \
      -DCMAKE_SYSROOT=/path/to/rpi-sysroot \
      -DTARGET_DEVICE=STSAFE_A110 \
      -DDEPLOY_TARGET=pi@raspberrypi.local \
      -DDEPLOY_EXAMPLES_DIR=/home/pi/stse-linux

cmake --build build/rpi -j$(nproc)
cmake --build build/rpi --target deploy
```

---

## 4. Running Examples on Raspberry Pi

Log into the Raspberry Pi or open a terminal:

```bash
# Export the OpenSSL provider directory
export OPENSSL_MODULES=$(openssl version -a | grep MODULESDIR | awk '{print $2}' | tr -d '"')

# Navigate to built/deployed binaries
cd build  # (if built natively) or cd /home/pi/stse-linux/stsafe-a110 (if deployed via SSH)

# Test I2C echo
./01_Echo_loop

# Test device authentication
./01_Device_authentication

# Run OpenSSL provider ECDSA sign/verify demo (bus 1, slot 1)
./02_OpenSSL_ecdsa_sign_verify 1 1
```
