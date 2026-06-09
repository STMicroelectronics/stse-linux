# 01\_Secure\_data\_storage\_zone\_access

## Purpose

Demonstrates reading from and writing to a STSAFE-A120 secure data zone.  The example:

1. Writes a test buffer to a configurable data zone.
2. Reads back the content.
3. Compares the written and read data byte-by-byte.

This serves as a reference for any application that needs to store secrets, certificates, or configuration data in the device's non-volatile memory with access control.

## Architecture

```
01_Secure_data_storage_zone_access  →  libstse.so (stse_write_data_zone, stse_read_data_zone)
                                    →  STSELib_Platform IPC proxy
                                    →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 with at least one writable data zone |
| Runtime | `se-daemon` running, `libstse.so` installed |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

> **Note:** The target data zone must be configured with write access enabled.  Use `02_Command_AC_provisioning` if access control changes are needed.

## Cross-Compile

```bash
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
# or: export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 01_Secure_data_storage_zone_access
```

Binary produced at `build/01_Secure_data_storage_zone_access`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
# or:
scp build/01_Secure_data_storage_zone_access root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
./01_Secure_data_storage_zone_access          # default /dev/i2c-1
./01_Secure_data_storage_zone_access 5        # use /dev/i2c-5
```

### Expected Output

```
 - Write test buffer to zone 1 ...  OK
 - Read back zone 1 ...  OK
 - Compare buffers ...  MATCH

Secure data storage zone access: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| Write error `0x0401` | Zone access control does not allow write; run `02_Command_AC_provisioning` |
| Read/write mismatch | Zone may overlap with a reserved area; check zone configuration |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
