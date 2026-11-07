# Troubleshooting & Frequently Asked Questions (FAQ)

This document covers common issues, debugging steps, error codes, and practical questions when working with the **STSAFE Linux Middleware** (`se-daemon`, `libstse.so`, and OpenSSL 3.x providers).

---

## Table of Contents

1. [se-daemon Issues](#1-se-daemon-issues)
2. [OpenSSL 3.x Provider Issues](#2-openssl-3x-provider-issues)
3. [STSELib & I²C Communication Errors](#3-stselib--ic-communication-errors)
4. [Cryptographic Operations & Slot Access Conditions](#4-cryptographic-operations--slot-access-conditions)
5. [Build & Cross-Compilation FAQ](#5-build--cross-compilation-faq)
6. [Multi-Process & Concurrency FAQ](#6-multi-process--concurrency-faq)

---

## 1. se-daemon Issues

### `Failed to open I²C bus` or `se-daemon.service failed`

**Symptom:**
`systemctl status se-daemon` reports that the service failed to start with `Failed to open I²C bus /dev/i2c-N`.

**Causes & Solutions:**
1. **Wrong bus number:**
   Identify the correct I²C bus where the STSAFE secure element is connected:
   ```bash
   ls -la /dev/i2c-*
   i2cdetect -y 1
   ```
   If your board uses a different bus (e.g. `/dev/i2c-2`), update the service file `/etc/systemd/system/se-daemon.service`:
   ```ini
   ExecStart=/usr/local/sbin/se-daemon --bus 2
   ```
   Reload and restart:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart se-daemon
   ```

2. **Kernel module `i2c-dev` is not loaded:**
   Verify if `/dev/i2c-*` devices exist. If not, load the kernel driver:
   ```bash
   sudo modprobe i2c-dev
   echo "i2c-dev" | sudo tee -a /etc/modules-load.d/i2c.conf
   ```

3. **On Raspberry Pi:**
   Ensure I²C is enabled in device tree configuration:
   ```bash
   sudo raspi-config nonint do_i2c 0
   ```

---

### `Cannot connect to daemon socket: /var/run/se-daemon.sock`

**Symptom:**
Application fails when initializing the STSE library or provider: `Failed to connect to se-daemon socket`.

**Causes & Solutions:**
1. **Daemon is not running:**
   ```bash
   sudo systemctl status se-daemon
   ```
   Start it with:
   ```bash
   sudo systemctl start se-daemon
   ```
2. **Permission denied:**
   Check socket permissions:
   ```bash
   ls -l /var/run/se-daemon.sock
   ```
   By default, `se-daemon` runs as root with `UMask=0117` (group read/write). Ensure your application user belongs to the group configured in `se-daemon.service` (or run as root/member of the `i2c` group).

---

## 2. OpenSSL 3.x Provider Issues

### `OSSL_PROVIDER_load()` returns `NULL`

**Symptom:**
Application reports `OSSL_PROVIDER_load("stsafe-a120") failed` or provider cannot be found.

**Causes & Solutions:**
1. **`OPENSSL_MODULES` environment variable not set:**
   OpenSSL looks for providers in the path defined by the `MODULESDIR` configuration or the `OPENSSL_MODULES` environment variable.
   Export the proper path dynamically:
   ```bash
   export OPENSSL_MODULES=$(openssl version -a | grep MODULESDIR | awk '{print $2}' | tr -d '"')
   ```
   Or set it permanently in `/etc/environment`.
2. **Provider `.so` is not installed:**
   Verify that the `.so` exists in the modules directory:
   ```bash
   ls -la $OPENSSL_MODULES/stsafe-*.so
   ```
3. **Architecture / ABI Mismatch:**
   Ensure the provider shared object matches the host architecture:
   ```bash
   file $OPENSSL_MODULES/stsafe-a120.so
   ```

---

### Provider loads, but operations fail (`EVP_PKEY_generate` or `EVP_DigestSignInit`)

**Symptom:**
`EVP_PKEY_CTX_new_from_name` fails or returns NULL when initializing key operations.

**Causes & Solutions:**
1. **Property query string mismatch:**
   Ensure the query string matches the exact provider name:
   - STSAFE-A120: `"provider=stsafe-a120"`
   - STSAFE-A110: `"provider=stsafe-a110"`
   - STSAFE-L010: `"provider=stsafe-l010"`
2. **Default fallback provider missing:**
   For operations delegating software checks (e.g., STSAFE-L010 verification, general digest handling), the OpenSSL `default` provider must also be loaded:
   ```c
   OSSL_PROVIDER_load(NULL, "default");
   ```

---

## 3. STSELib & I²C Communication Errors

### `stse_init ERROR : 0x0001` or `0x0002`

| Error Code | Name | Cause | Resolution |
|---|---|---|---|
| `0x0001` | Bus Open Failed | Socket could not be opened or bus parameter is invalid. | Check if `se-daemon` is active and socket exists. |
| `0x0002` | Device Not Responding | No I²C ACK from the device address (`0x20` or `0x0C`). | Verify wiring (SDA/SCL reversed, missing pull-ups, power pin disconnected). Scan with `i2cdetect -y 1`. |
| `0x0003` | Protocol Error | Framing error, unexpected CRC, or bus glitch. | Power-cycle the secure element board; inspect I²C pull-up resistor values (typically 2.2kΩ to 4.7kΩ). |

---

## 4. Cryptographic Operations & Slot Access Conditions

### Key generation fails with error `0x0011` / `err 17`

**Symptom:**
`02_OpenSSL_ecdsa_sign_verify` or `01_Key_pair_generation_NIST_P256` prints `keygen failed, error 0x0011`.

**Cause:**
Secure element key slots have configurable **Access Conditions (AC)**. In pre-provisioned or factory devices, slot 0 is often locked or requires authentication before overwriting.

**Solution:**
Target a different slot index (e.g., slot 1):
```bash
./02_OpenSSL_ecdsa_sign_verify 1 1   # arg 1: busID, arg 2: slotID
```
Or run the provisioning examples to update slot access conditions if authorized.

---

### STSAFE-L010: `L010 requires strictly 16-byte challenge`

**Symptom:**
Signing with `stsafe-l010` fails when executing `EVP_DigestSign()`.

**Cause:**
STSAFE-L010 is designed for lightweight challenge-response authentication. Unlike general-purpose curve engines, the hardware sign instruction expects a raw **16-byte challenge buffer**, not an arbitrary-length message or pre-computed SHA-256 hash.

**Solution:**
Pass an exact 16-byte challenge to `EVP_DigestSign`:
```c
unsigned char challenge[16];
RAND_bytes(challenge, sizeof(challenge));
EVP_DigestSign(sign_ctx, signature, &sig_len, challenge, sizeof(challenge));
```

---

## 5. Build & Cross-Compilation FAQ

### `openssl/opensslconf.h: No such file or directory`
- **Cause:** Compiling with a cross-compiler without setting sysroot headers, or using host headers on a cross target.
- **Fix:** If using OpenSTLinux, ensure you sourced the SDK environment script:
  ```bash
  source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
  ```
  If cross-compiling for Raspberry Pi, ensure `-DCMAKE_SYSROOT` points to a sysroot with `libssl-dev` installed.

### `STSELib submodule is not initialised`
Run:
```bash
git submodule update --init lib/STSELib
cd lib/STSELib && git checkout remotes/origin/feature/pkcs11 && cd -
```

### `libstse.so: cannot open shared object file`
- **Cause:** The dynamic linker cannot find `libstse.so`.
- **Fix:** Make sure `/usr/local/lib` is in the dynamic linker configuration:
  ```bash
  echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/stse.conf
  sudo ldconfig
  ```

---

## 6. Multi-Process & Concurrency FAQ

### Can multiple processes access the secure element at the same time?
**Yes.** All communications pass through `se-daemon` via Unix domain sockets. The daemon serializes each atomic I²C transaction, making operations safely multi-process and multi-thread safe.

### Can STSAFE-A and STSAFE-L share the same I²C bus?
**Yes.**
- STSAFE-A110 / STSAFE-A120 use 7-bit I²C address `0x20`.
- STSAFE-L010 uses 7-bit I²C address `0x0C`.

Because their addresses do not conflict, both devices can be connected in parallel on the same physical I²C lines.
