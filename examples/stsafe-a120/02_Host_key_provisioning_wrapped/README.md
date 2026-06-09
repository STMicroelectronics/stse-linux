# 02\_Host\_key\_provisioning\_wrapped

## Purpose

Provisions a host pairing key into the STSAFE-A120 using **AES key wrapping**.  The key is encrypted by a KEK (Key Encryption Key) before being sent to the device, so the plaintext key is never exposed on the I²C bus.  This is the recommended production-safe alternative to `02_Host_key_provisioning`.

The example:
1. Generates a 256-bit AES host key on the host.
2. Wraps it with a KEK using `stse_platform_aes_key_wrap` (AES-256 key wrap, RFC 3394).
3. Sends the wrapped key to the STSAFE-A120 via `stsafea_put_host_key_wrapped`.

## Architecture

```
02_Host_key_provisioning_wrapped  →  libstse.so (stsafea_put_host_key_wrapped,
                                                   stse_platform_aes_key_wrap)
                                  →  STSELib_Platform IPC proxy
                                  →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 with host key slot in writable state and matching KEK pre-provisioned |
| Runtime | `se-daemon` running, `libstse.so` installed |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

## Cross-Compile

```bash
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
# or: export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 02_Host_key_provisioning_wrapped
```

Binary produced at `build/02_Host_key_provisioning_wrapped`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
# or:
scp build/02_Host_key_provisioning_wrapped root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
./02_Host_key_provisioning_wrapped          # default /dev/i2c-1
./02_Host_key_provisioning_wrapped 5        # use /dev/i2c-5
```

### Expected Output

```
 - Wrap host key with KEK ...  OK
 - Write wrapped host key to slot 0 ...  OK
 - Host key (wrapped) provisioning: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| Unwrap error on device | KEK mismatch between host and device; re-check KEK value |
| Write error | Slot AC does not allow wrapped key write |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
