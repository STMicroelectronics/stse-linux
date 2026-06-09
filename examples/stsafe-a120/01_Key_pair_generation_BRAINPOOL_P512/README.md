# 01\_Key\_pair\_generation\_BRAINPOOL\_P512

## Purpose

Generates a Brainpool P-512r1 Elliptic Curve key pair on the STSAFE-A120.  The Brainpool curves are widely used in German/European regulatory contexts (BSI TR-03111).  The private key is stored in hardware; the public key (X, Y — 64 bytes each) is returned and printed.

## Architecture

```
01_Key_pair_generation_BRAINPOOL_P512  →  libstse.so (stse_generate_ecc_key_pair)
                                       →  STSELib_Platform IPC proxy
                                       →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 with a slot configured for Brainpool P-512 |
| Runtime | `se-daemon` running, `libstse.so` installed |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

## Cross-Compile

```bash
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
# or: export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 01_Key_pair_generation_BRAINPOOL_P512
```

Binary produced at `build/01_Key_pair_generation_BRAINPOOL_P512`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
# or:
scp build/01_Key_pair_generation_BRAINPOOL_P512 root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
./01_Key_pair_generation_BRAINPOOL_P512          # default /dev/i2c-1
./01_Key_pair_generation_BRAINPOOL_P512 5        # use /dev/i2c-5
```

### Expected Output

```
 - Generate Brainpool P-512 key pair on slot 0 ...
 - Public key X: <64 bytes>
 - Public key Y: <64 bytes>

Key pair generation BRAINPOOL P-512: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| `stse_generate_ecc_key_pair ERROR` | Check that the slot is configured for Brainpool P-512 and the AC allows generation |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
