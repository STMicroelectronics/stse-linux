# 02\_Command\_AC\_provisioning

## Purpose

Reads and displays the complete Command Authorisation Configuration (AC) table of the STSAFE-A120.  For each of the device's ~45 commands it prints the current Change Rights and Access Condition settings.  As an optional second step the example re-provisions selected AC entries.

This is typically the **first provisioning step** performed on a freshly received STSAFE-A120 before running any other example that depends on specific AC settings.

## Architecture

```
02_Command_AC_provisioning  →  libstse.so (stsafea_get_command_count,
                                            stsafea_get_command_AC_table,
                                            stsafea_put_command_AC_table)
                            →  STSELib_Platform IPC proxy
                            →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 |
| Runtime | `se-daemon` running, `libstse.so` installed |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

> **Warning:** Writing a new AC table is a one-way change for locked entries.  Review the desired AC values carefully before enabling the write path in the example.

## Cross-Compile

```bash
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
# or: export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 02_Command_AC_provisioning
```

Binary produced at `build/02_Command_AC_provisioning`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
# or:
scp build/02_Command_AC_provisioning root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
./02_Command_AC_provisioning          # default /dev/i2c-1
./02_Command_AC_provisioning 5        # use /dev/i2c-5
```

### Expected Output

```
 - stsafea_get_command_count: 45 commands
 - Command AC table:
   CMD 0x00  CR=0x55  AC=always
   CMD 0x01  CR=0x55  AC=always
   ...

Command AC provisioning: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| `stsafea_get_command_count ERROR` | `stse_init` failed; check I²C bus |
| Put AC table fails | Change Rights field for the target command may be locked |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
