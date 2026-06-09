# 04\_Symmetric\_key\_provisioning\_control\_fields

## Purpose

Provisions a symmetric key slot on the STSAFE-A120 by writing a new AES key together with its **control fields** (key type, key length, usage authorisation, and change rights).  This is the prerequisite step before any symmetric-key-based example (AES-CMAC, AES-CCM, key wrapping).

The example:
1. Displays the current control fields of the target symmetric key slot.
2. Writes a test AES-256 key and the desired control field configuration.
3. Reads back the control fields to confirm the write succeeded.

## Architecture

```
04_Symmetric_key_provisioning_control_fields  →  libstse.so
                                                   (stsafea_put_symmetric_key_slot,
                                                    stsafea_query_symmetric_key_slots_provisioning_ctrl_fields)
                                              →  STSELib_Platform IPC proxy
                                              →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 with at least one symmetric key slot in writable state |
| Runtime | `se-daemon` running, `libstse.so` installed |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

> **Warning:** Changing control fields for a locked slot is irreversible.  Verify the desired configuration before running.

## Cross-Compile

```bash
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
# or: export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 04_Symmetric_key_provisioning_control_fields
```

Binary produced at `build/04_Symmetric_key_provisioning_control_fields`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
# or:
scp build/04_Symmetric_key_provisioning_control_fields root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
./04_Symmetric_key_provisioning_control_fields          # default /dev/i2c-1
./04_Symmetric_key_provisioning_control_fields 5        # use /dev/i2c-5
```

### Expected Output

```
 - Query symmetric key slot 0 control fields ...
   Key type: AES-256  Usage: MAC+Wrap  Change rights: locked
 - Write new key + control fields to slot 0 ...  OK
 - Verify control fields ...  OK

Symmetric key provisioning (control fields): SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| Write error `0x0401` | Slot change rights are locked; provision a fresh device |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
