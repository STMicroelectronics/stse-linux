# 05\_Symmetric\_key\_provisioning\_wrapped\_compute\_AES-128\_CMAC

## Purpose

Combines **wrapped key provisioning** and **AES-128-CMAC computation** in one example:

1. Wraps a new AES-128 key using a KEK already present in the device.
2. Provisions the wrapped key into a target symmetric key slot via `stsafea_put_symmetric_key_wrapped`.
3. Immediately exercises the newly provisioned key by computing an AES-128-CMAC tag over a test message.
4. Verifies the tag against a software-computed reference.

This is the production-safe provisioning path: the plaintext key is never transmitted in clear over the I²C bus.

## Architecture

```
05_Symmetric_key_provisioning_wrapped_compute_AES-128_CMAC
    →  libstse.so (stsafea_put_symmetric_key_wrapped, stse_aes_cmac_compute)
    →  STSELib_Platform IPC proxy
    →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 with a KEK in slot 0 and a writable target slot |
| Runtime | `se-daemon` running, `libstse.so` installed |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

## Cross-Compile

```bash
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
# or: export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 05_Symmetric_key_provisioning_wrapped_compute_AES-128_CMAC
```

Binary produced at `build/05_Symmetric_key_provisioning_wrapped_compute_AES-128_CMAC`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
# or:
scp build/05_Symmetric_key_provisioning_wrapped_compute_AES-128_CMAC root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
./05_Symmetric_key_provisioning_wrapped_compute_AES-128_CMAC          # /dev/i2c-1
./05_Symmetric_key_provisioning_wrapped_compute_AES-128_CMAC 5        # /dev/i2c-5
```

### Expected Output

```
 - Wrap AES-128 key with KEK slot 0 ...  OK
 - Provision wrapped key to slot 1 ...  OK
 - Compute CMAC (STSAFE-A120): <16 bytes>
 - Compute CMAC (OpenSSL ref):  <16 bytes>
 - CMAC comparison: MATCH

Wrapped provisioning + AES-128 CMAC: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| Wrapped provisioning error | KEK slot or target slot AC mismatch |
| CMAC mismatch | Wrapped key decryption may have used wrong KEK; verify KEK value |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
