# 03\_Key\_wrapping

## Purpose

Demonstrates AES key wrapping and unwrapping using the STSAFE-A120 hardware:

1. A 256-bit AES key is generated on the host.
2. The key is wrapped (encrypted) by the STSAFE-A120 using a wrapping key stored in a symmetric key slot (`stse_aes_key_wrap`).
3. The wrapped ciphertext is then unwrapped by the device (`stse_aes_key_unwrap`).
4. The recovered plaintext is compared to the original to verify correctness.

Key wrapping allows secrets to be transported or stored without exposure, following RFC 3394 / NIST SP 800-38F.

## Architecture

```
03_Key_wrapping  →  libstse.so (stse_aes_key_wrap, stse_aes_key_unwrap)
                 →  STSELib_Platform IPC proxy
                 →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 with a symmetric key slot loaded with a wrapping KEK |
| Runtime | `se-daemon` running, `libstse.so` installed |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

> **Note:** Run `04_Symmetric_key_provisioning_control_fields` first to ensure the symmetric key slot is properly configured.

## Cross-Compile

```bash
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
# or: export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 03_Key_wrapping
```

Binary produced at `build/03_Key_wrapping`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
# or:
scp build/03_Key_wrapping root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
./03_Key_wrapping          # default /dev/i2c-1
./03_Key_wrapping 5        # use /dev/i2c-5
```

### Expected Output

```
 - Wrap 256-bit key using slot 0 KEK ...  OK
   Wrapped key: <40 bytes>
 - Unwrap key ...  OK
   Recovered key: <32 bytes>
 - Key wrap/unwrap comparison: MATCH

Key wrapping: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| Wrap error | KEK slot not initialised; run `04_Symmetric_key_provisioning_control_fields` |
| Wrap/unwrap mismatch | Possible endianness or padding issue in the ICV; contact ST support |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
