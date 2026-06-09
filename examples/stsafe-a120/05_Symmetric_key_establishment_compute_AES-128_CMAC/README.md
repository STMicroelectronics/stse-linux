# 05\_Symmetric\_key\_establishment\_compute\_AES-128\_CMAC

## Purpose

Demonstrates the AES-128 CMAC (Cipher-based Message Authentication Code) operation using a symmetric key stored in the STSAFE-A120.  The example:

1. Sends a message to the device.
2. The device computes a 16-byte CMAC tag over the message using the AES-128 key in a pre-provisioned symmetric key slot.
3. The host independently computes the same CMAC using OpenSSL with the known key.
4. Both tags are compared to verify correctness.

This demonstrates how the STSAFE-A120 can be used for **message authentication** in symmetric-key protocols (e.g., IoT sensor data integrity).

## Architecture

```
05_Symmetric_key_establishment_compute_AES-128_CMAC  →  libstse.so (stse_aes_cmac_compute)
                                                     →  STSELib_Platform IPC proxy
                                                     →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 with symmetric key slot 0 loaded with a known AES-128 key |
| Runtime | `se-daemon` running, `libstse.so` installed, OpenSSL 3.x |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

> **Note:** Run `04_Symmetric_key_provisioning_control_fields` first to provision the AES-128 key into slot 0.

## Cross-Compile

```bash
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
# or: export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 05_Symmetric_key_establishment_compute_AES-128_CMAC
```

Binary produced at `build/05_Symmetric_key_establishment_compute_AES-128_CMAC`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
# or:
scp build/05_Symmetric_key_establishment_compute_AES-128_CMAC root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
./05_Symmetric_key_establishment_compute_AES-128_CMAC          # default /dev/i2c-1
./05_Symmetric_key_establishment_compute_AES-128_CMAC 5        # /dev/i2c-5
```

### Expected Output

```
 - Message: <hex bytes>
 - CMAC (STSAFE-A120 hardware): <16 bytes>
 - CMAC (OpenSSL software):     <16 bytes>
 - CMAC comparison: MATCH

AES-128 CMAC compute: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| CMAC mismatch | Key in device slot does not match the reference key in the example; re-provision |
| `stse_aes_cmac_compute ERROR` | Symmetric key slot AC does not allow MAC operations |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
