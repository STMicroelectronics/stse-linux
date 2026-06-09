# 01\_Echo\_loop

## Purpose

Verifies basic I²C communication with the STSAFE-A120 by sending 10 randomly-sized messages (1–500 bytes) to the device's `Echo` command and comparing each echoed response byte-by-byte.  This is the recommended first test after hardware bring-up.

## Architecture

```
01_Echo_loop  →  libstse.so (stse_device_echo)
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

# From the repository root
cd /path/to/stse-linux
make 01_Echo_loop          # build this example only
# or
make                       # build everything
```

The binary is produced at `build/01_Echo_loop`.

## Deploy

```bash
# Replace root@192.168.1.100 with your target address
make deploy TARGET=root@192.168.1.100
```

`make deploy` transfers:
- `build/se-daemon`       → `/usr/sbin/se-daemon`
- `build/libstse.so.1.0`  → `/usr/lib/` (with symlinks + `ldconfig`)
- `build/01_Echo_loop`    → `/usr/bin/01_Echo_loop`  *(if using install target)*
- `daemon/se-daemon.service` → `/etc/systemd/system/`

To copy only the example binary:
```bash
scp build/01_Echo_loop root@192.168.1.100:/home/root/
```

## Install on Target

The `deploy` target already installs the daemon and library. If you copied the binary manually, no extra installation is needed — the binary uses `libstse.so` from `/usr/lib/`.

Enable the daemon to start automatically:
```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
ssh root@192.168.1.100

# Default: uses /dev/i2c-1
./01_Echo_loop

# Explicit bus (e.g. /dev/i2c-5)
./01_Echo_loop 5
```

### Expected Output

```
----------------------------------------------------------------------------------------------------------------
-                                   STSAFE-A Echo loop example                                                -
----------------------------------------------------------------------------------------------------------------
 - Initialize target STSAFE-A120 on /dev/i2c-1
 ## Message (123 bytes):
   AB CD EF ...
 ## Echoed Message:
   AB CD EF ...
*#*# STMICROELECTRONICS #*#*
...
 Echo loop completed successfully.
```

## Troubleshooting

| Error code | Meaning | Action |
|------------|---------|--------|
| `0x0101` `STSE_PLATFORM_BUS_ACK_ERROR` | I²C NACK — device not found | Check wiring, I²C bus number, `se-daemon --bus N` |
| `0x0303` `STSE_SERVICE_FRAME_CRC_ERROR` | CRC mismatch in response | Verify `libstse.so` version matches source; try `se-daemon --debug` |
| `libstse.so: not found` | Dynamic linker cannot find library | Run `ldconfig` on target; check `/usr/lib/libstse.so.1` exists |
| `connect: No such file or socket` | `se-daemon` not running | `systemctl start se-daemon` |
