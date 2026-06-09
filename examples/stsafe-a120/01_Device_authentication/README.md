# 01\_Device\_authentication

## Purpose

Demonstrates full certificate-chain device authentication of the STSAFE-A120.  The example:

1. Reads the device certificate from data zone 0.
2. Verifies the leaf certificate against the hardcoded ST **SPL05 Production CA 01** root certificate.
3. Issues a challenge using `stse_ecc_sign` with static private key slot 0.
4. Verifies the ECDSA signature with the public key extracted from the device certificate.

This provides a reference implementation for authenticating an STSAFE-A120 from a Linux host — analogous to what a distant server would perform.

## Architecture

```
01_Device_authentication  →  libstse.so (stse_init, stse_get_x509_cert, stse_ecc_sign)
                          →  STSELib_Platform IPC proxy
                          →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 SPL05 provisioned with ST Production CA cert in zone 0 |
| Runtime | `se-daemon` running, `libstse.so` installed |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

## Cross-Compile

```bash
# Option A — OpenSTLinux SDK (recommended)
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi

# Option B — bare cross-toolchain
export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 01_Device_authentication
# or
make
```

Binary produced at `build/01_Device_authentication`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
```

To copy only the binary:
```bash
scp build/01_Device_authentication root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
ssh root@192.168.1.100

# Default: uses /dev/i2c-1
./01_Device_authentication

# Explicit bus
./01_Device_authentication 5
```

### Expected Output

```
----------------------------------------------------------------------------------------------------------------
-                          STSAFE-A120 Device Authentication Example                                         -
...
 - Reading device certificate from zone 0 ...  OK
 - Verifying certificate against ST CA 01 ...  OK
 - Generating challenge and requesting signature ...  OK
 - Verifying ECDSA signature ...  OK

Device Authentication: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| Certificate verification failed | Ensure STSAFE-A120 is provisioned with SPL05 CA; check CA certificate bytes in `main.c` |
| `stse_ecc_sign ERROR` | Static key slot 0 may require host key pairing; see `02_Host_key_provisioning` |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
