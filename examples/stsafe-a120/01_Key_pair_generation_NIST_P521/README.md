# 01\_Key\_pair\_generation\_NIST\_P521

## Purpose

Generates a NIST P-521 (secp521r1) Elliptic Curve key pair on the STSAFE-A120 hardware.  P-521 provides 260-bit security strength.  The private key is stored securely inside the device; the public key (X, Y — 66 bytes each) is returned and printed.

## Architecture

```
01_Key_pair_generation_NIST_P521  →  libstse.so (stse_generate_ecc_key_pair)
                                  →  STSELib_Platform IPC proxy
                                  →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 with a writable generic key slot supporting P-521 |
| Runtime | `se-daemon` running, `libstse.so` installed |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

## Cross-Compile

```bash
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
# or: export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 01_Key_pair_generation_NIST_P521
```

Binary produced at `build/01_Key_pair_generation_NIST_P521`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
# or manual copy:
scp build/01_Key_pair_generation_NIST_P521 root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
./01_Key_pair_generation_NIST_P521          # default /dev/i2c-1
./01_Key_pair_generation_NIST_P521 5        # use /dev/i2c-5
```

### Expected Output

```
 - Generate NIST P-521 key pair on slot 0 ...
 - Public key X: <66 bytes>
 - Public key Y: <66 bytes>

Key pair generation NIST P-521: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| `stse_generate_ecc_key_pair ERROR` | Verify P-521 is supported on the target slot; check AC state |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
