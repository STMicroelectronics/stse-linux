# 05\_Symmetric\_key\_establishment\_encrypt\_AES-256\_CCM

## Purpose

Demonstrates authenticated encryption and decryption using AES-256-CCM (Counter with CBC-MAC) with a symmetric key stored in the STSAFE-A120.  The example:

1. Encrypts a plaintext message on the STSAFE-A120 hardware using `stse_aes_ccm_encrypt`.
2. Decrypts the resulting ciphertext + authentication tag back on the hardware using `stse_aes_ccm_decrypt`.
3. Compares the decrypted output to the original plaintext.

AES-256-CCM provides both **confidentiality** and **integrity** in a single pass, making it suitable for IoT communication payloads.

## Architecture

```
05_Symmetric_key_establishment_encrypt_AES-256_CCM  →  libstse.so (stse_aes_ccm_encrypt,
                                                                      stse_aes_ccm_decrypt)
                                                    →  STSELib_Platform IPC proxy
                                                    →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 with symmetric key slot 0 loaded with an AES-256 key |
| Runtime | `se-daemon` running, `libstse.so` installed |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

> **Note:** Run `04_Symmetric_key_provisioning_control_fields` first to provision the AES-256 key.

## Cross-Compile

```bash
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
# or: export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 05_Symmetric_key_establishment_encrypt_AES-256_CCM
```

Binary produced at `build/05_Symmetric_key_establishment_encrypt_AES-256_CCM`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
# or:
scp build/05_Symmetric_key_establishment_encrypt_AES-256_CCM root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
./05_Symmetric_key_establishment_encrypt_AES-256_CCM          # default /dev/i2c-1
./05_Symmetric_key_establishment_encrypt_AES-256_CCM 5        # /dev/i2c-5
```

### Expected Output

```
 - Plaintext:   <hex bytes>
 - Ciphertext:  <hex bytes>
 - Auth tag:    <hex bytes>
 - Decrypted:   <hex bytes>
 - Plaintext == Decrypted: MATCH

AES-256-CCM encrypt/decrypt: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| Authentication tag failure | Nonce or AAD mismatch between encrypt and decrypt calls |
| `stse_aes_ccm_encrypt ERROR` | Key slot not configured for encryption; check AC |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
