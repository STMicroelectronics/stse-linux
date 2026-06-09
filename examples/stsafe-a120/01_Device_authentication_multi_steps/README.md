# 01\_Device\_authentication\_multi\_steps

## Purpose

Extended variant of `01_Device_authentication` that performs device authentication in discrete steps, making each intermediate operation visible:

1. Query and display the command authorisation configuration.
2. Read the device X.509 certificate from zone 0.
3. Verify the certificate chain against the ST SPL05 Production CA 01 root certificate.
4. Generate a random challenge nonce.
5. Request an ECDSA signature over the nonce from static key slot 0.
6. Verify the signature using the public key from the device certificate.

This step-by-step approach is suited for educational use and for integrating individual stages into larger application flows (e.g., network-based authentication protocols).

## Architecture

```
01_Device_authentication_multi_steps  →  libstse.so
                                      →  STSELib_Platform IPC proxy
                                      →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 |
| Secure element | STSAFE-A120 SPL05 with ST Production CA certificate in zone 0 |
| Runtime | `se-daemon` running, `libstse.so` installed |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set |

## Cross-Compile

```bash
# Option A — OpenSTLinux SDK (recommended)
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi

# Option B — bare cross-toolchain
export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 01_Device_authentication_multi_steps
# or
make
```

Binary produced at `build/01_Device_authentication_multi_steps`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
```

To copy only the binary:
```bash
scp build/01_Device_authentication_multi_steps root@192.168.1.100:/home/root/
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

```bash
ssh root@192.168.1.100

./01_Device_authentication_multi_steps         # default /dev/i2c-1
./01_Device_authentication_multi_steps 5       # use /dev/i2c-5
```

### Expected Output

```
Step 1 — Query command AC config ...  OK
Step 2 — Read device certificate from zone 0 ...  OK  (xxx bytes)
Step 3 — Verify certificate chain ...  OK
Step 4 — Generate challenge nonce ...  OK
Step 5 — Request ECDSA signature ...  OK
Step 6 — Verify signature ...  OK

Multi-step Device Authentication: SUCCESS
```

## Troubleshooting

| Error | Action |
|-------|--------|
| Certificate chain verification fails | Confirm SPL05 provisioning; double-check CA certificate |
| Signature verification fails | Key slot 0 mismatch; re-run after host key provisioning |
| `stse_init ERROR` | Check I²C bus and `se-daemon` status |
