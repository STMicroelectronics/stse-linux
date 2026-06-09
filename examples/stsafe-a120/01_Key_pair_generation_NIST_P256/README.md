# 01\_Key\_pair\_generation\_NIST\_P256

## Purpose

Generates a NIST P-256 (secp256r1) Elliptic Curve key pair on the STSAFE-A120 hardware using `stse_generate_ecc_key_pair`.  The private key never leaves the secure element.  The example retrieves and prints the public key coordinates (X, Y) and can be used as a starting point for ECDH or signing workflows.

## Architecture

```
01_Key_pair_generation_NIST_P256  →  libstse.so (stse_generate_ecc_key_pair)
                                  →  STSELib_Platform IPC proxy
                                  →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 with at least one writable generic key slot |
| Runtime | `se-daemon` running, `libstse.so` installed |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

> **Note:** Key generation requires that the target slot is in the correct authorisation state (typically AC = `always`).  Use `02_Command_AC_provisioning` to adjust if needed.

## Cross-Compile

```bash
# Option A — OpenSTLinux SDK (recommended)
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi

# Option B — bare cross-toolchain
export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 01_Key_pair_generation_NIST_P256
# or
make
```

Binary produced at `build/01_Key_pair_generation_NIST_P256`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
```

To copy only the binary:
```bash
scp build/01_Key_pair_generation_NIST_P256 root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
ssh root@192.168.1.100

./01_Key_pair_generation_NIST_P256          # default /dev/i2c-1
./01_Key_pair_generation_NIST_P256 5        # use /dev/i2c-5
```

### Expected Output

```
 - Generate NIST P-256 key pair on slot 0 ...
 - Public key X: 4A 2C ... (32 bytes)
 - Public key Y: 8F 01 ... (32 bytes)

Key pair generation NIST P-256: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| `stse_generate_ecc_key_pair ERROR 0x0401` | Slot locked; check AC configuration |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
