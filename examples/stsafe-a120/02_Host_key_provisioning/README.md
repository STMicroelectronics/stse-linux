# 02\_Host\_key\_provisioning

## Purpose

Provisions a **host pairing key** into the STSAFE-A120.  The host key enables MAC-protected communication between the Linux host and the device, which is required for commands whose AC is set to `host` (MAC-verified).

The example:
1. Generates or uses a pre-defined 256-bit AES host key on the host.
2. Writes it in plaintext to the designated host key slot using `stsafea_put_host_key`.
3. Reads back and verifies the key was accepted.

> **Security note:** Plaintext key injection is only acceptable in a secure factory environment.  For production use, prefer `02_Host_key_provisioning_wrapped`.

## Architecture

```
02_Host_key_provisioning  →  libstse.so (stsafea_put_host_key)
                          →  STSELib_Platform IPC proxy
                          →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 with host key slot in writable state |
| Runtime | `se-daemon` running, `libstse.so` installed |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

## Cross-Compile

```bash
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
# or: export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 02_Host_key_provisioning
```

Binary produced at `build/02_Host_key_provisioning`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
# or:
scp build/02_Host_key_provisioning root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
./02_Host_key_provisioning          # default /dev/i2c-1
./02_Host_key_provisioning 5        # use /dev/i2c-5
```

### Expected Output

```
 - Write host key to slot 0 ...  OK
 - Host key provisioning: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| Write error | Host key slot AC does not allow plaintext write; use wrapped variant |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
