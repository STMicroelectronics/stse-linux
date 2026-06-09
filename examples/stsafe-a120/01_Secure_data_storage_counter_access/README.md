# 01\_Secure\_data\_storage\_counter\_access

## Purpose

Demonstrates the monotonic counter functionality of the STSAFE-A120.  The example reads the current counter value, increments it, and reads it back to verify the increment.  Monotonic counters are used for anti-replay protection, firmware version tracking, and tamper-evidence.

## Architecture

```
01_Secure_data_storage_counter_access  →  libstse.so (stse_read_data_zone, stse_increment_data_zone_counter)
                                       →  STSELib_Platform IPC proxy
                                       →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 with a counter-type data zone |
| Runtime | `se-daemon` running, `libstse.so` installed |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

> **Warning:** Counter increments are irreversible.  The STSAFE-A120 supports a limited number of increment operations per counter zone.

## Cross-Compile

```bash
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
# or: export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 01_Secure_data_storage_counter_access
```

Binary produced at `build/01_Secure_data_storage_counter_access`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
# or:
scp build/01_Secure_data_storage_counter_access root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
./01_Secure_data_storage_counter_access          # default /dev/i2c-1
./01_Secure_data_storage_counter_access 5        # use /dev/i2c-5
```

### Expected Output

```
 - Read counter zone ...  Value: 0x00000005
 - Increment counter ...  OK
 - Read counter zone ...  Value: 0x00000006

Secure data storage counter access: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| Counter zone not found | Verify device personalisation includes a counter-type zone |
| Increment error `0x0401` | Access control restricts increment; adjust via `02_Command_AC_provisioning` |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
