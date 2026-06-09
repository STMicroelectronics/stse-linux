# 05\_Symmetric\_key\_provisioning\_wrapped\_encrypt\_AES-256\_CCM

## Purpose

Combines **wrapped key provisioning** and **AES-256-CCM authenticated encryption** in one example:

1. Wraps a new AES-256 key using a KEK already present in the device.
2. Provisions the wrapped key into a target symmetric key slot via `stsafea_put_symmetric_key_wrapped`.
3. Encrypts a test plaintext with AES-256-CCM on the hardware using the newly provisioned key.
4. Decrypts and verifies the result.

This is the production-safe provisioning path for encryption keys.

## Architecture

```
05_Symmetric_key_provisioning_wrapped_encrypt_AES-256_CCM
    →  libstse.so (stsafea_put_symmetric_key_wrapped,
                   stse_aes_ccm_encrypt, stse_aes_ccm_decrypt)
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
make 05_Symmetric_key_provisioning_wrapped_encrypt_AES-256_CCM
```

Binary produced at `build/05_Symmetric_key_provisioning_wrapped_encrypt_AES-256_CCM`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
# or:
scp build/05_Symmetric_key_provisioning_wrapped_encrypt_AES-256_CCM root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
./05_Symmetric_key_provisioning_wrapped_encrypt_AES-256_CCM          # /dev/i2c-1
./05_Symmetric_key_provisioning_wrapped_encrypt_AES-256_CCM 5        # /dev/i2c-5
```

### Expected Output

```
 - Wrap AES-256 key with KEK slot 0 ...  OK
 - Provision wrapped key to slot 1 ...  OK
 - Encrypt plaintext (AES-256-CCM) ...  OK
 - Decrypt ciphertext ...  OK
 - Plaintext == Decrypted: MATCH

Wrapped provisioning + AES-256-CCM encrypt: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| Wrapped provisioning error | Verify KEK slot and target slot AC configuration |
| Decryption authentication failure | Nonce or AAD mismatch; check example constants |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
