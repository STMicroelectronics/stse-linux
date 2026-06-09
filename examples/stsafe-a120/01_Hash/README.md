# 01\_Hash

## Purpose

Demonstrates SHA-256 hashing on the STSAFE-A120 secure element.  A 128-byte random buffer is hashed twice in parallel — once by the host OpenSSL platform layer (`stse_platform_hash_compute`) and once on the STSAFE-A120 hardware (`stse_compute_hash`).  The two digests are compared to verify that both implementations produce identical results.

## Architecture

```
01_Hash  →  libstse.so (stse_compute_hash + stse_platform_hash_compute)
         →  STSELib_Platform IPC proxy
         →  se-daemon (Unix socket /var/run/se-daemon.sock)
         →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 at I²C address 0x20 |
| Runtime | `se-daemon` running on target, `libstse.so` installed |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

## Cross-Compile

```bash
# Option A — OpenSTLinux SDK (recommended)
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi

# Option B — bare cross-toolchain
export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 01_Hash
# or
make
```

Binary produced at `build/01_Hash`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
```

To copy only the binary:
```bash
scp build/01_Hash root@192.168.1.100:/home/root/
```

## Install on Target

```bash
# Ensure daemon and library are installed (done by make deploy)
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
ssh root@192.168.1.100

# Default: uses /dev/i2c-1
./01_Hash

# Explicit bus (e.g. /dev/i2c-5)
./01_Hash 5
```

### Expected Output

```
----------------------------------------------------------------------------------------------------------------
-                                      STSAFE-A120 hash commands example                                      -
...
 - Message buffer to hash:
   <128 hex bytes>

 - stse_platform_hash_compute (SHA-256):
   <32-byte digest>

 - stse_compute_hash (STSAFE-A120):
   <32-byte digest>

Hash comparison: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| `stse_init ERROR` | Check I²C bus, `se-daemon` running |
| `stse_platform_hash_compute ERROR` | OpenSSL not linked correctly; check `libstse.so` build |
| Hash mismatch | Possible firmware version mismatch; check STSAFE-A120 firmware |
