# 06\_GTK\_Authentication\_Demo

## Purpose

A graphical (GTK3) desktop application that demonstrates STSAFE-A120 device authentication through a point-and-click interface.  The user presses the **Authenticate** button; the application then:

1. Reads the device X.509 certificate from data zone 0.
2. Verifies it against the hardcoded ST SPL05 Production CA 01 root certificate.
3. Generates a random challenge nonce.
4. Requests an ECDSA signature from static key slot 0 on the STSAFE-A120.
5. Verifies the signature with the public key from the device certificate.
6. Displays a **PASS / FAIL** result and a scrollable detailed log in the window.

This demo is suitable for trade-show showcases or factory test stations with a display attached to the STM32MP1 board.

## Architecture

```
06_GTK_Authentication_Demo  →  libstse.so (stse_init, certificate read, stse_ecc_sign)
                            →  STSELib_Platform IPC proxy
                            →  se-daemon  →  /dev/i2c-N  →  STSAFE-A120
                            GTK3 UI thread  ←→  pthread worker
```

## Prerequisites

| Item | Details |
|------|---------|
| Target board | STM32MP1 running OpenSTLinux 6.6 with Weston/Wayland or X11 |
| Secure element | STSAFE-A120 SPL05 with ST Production CA certificate in zone 0 |
| Runtime | `se-daemon` running, `libstse.so` installed, GTK3 runtime libraries |
| Build host | OpenSTLinux SDK sourced **or** `CROSS_COMPILE` set; `pkg-config gtk+-3.0` must resolve |

### Install GTK3 SDK headers on build host

When using the OpenSTLinux SDK, GTK3 development headers are typically included.  If missing:
```bash
# On Ubuntu/Debian build host (for native build only):
sudo apt install libgtk-3-dev
```

For cross-compilation the GTK3 `.pc` files must be present in the SDK sysroot.

## Cross-Compile

```bash
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
# or: export CROSS_COMPILE=arm-ostl-linux-gnueabi-

cd /path/to/stse-linux
make 06_GTK_Authentication_Demo
```

If `pkg-config gtk+-3.0` fails, the build is silently skipped.  Verify with:
```bash
pkg-config --cflags gtk+-3.0
```

Binary produced at `build/06_GTK_Authentication_Demo`.

## Deploy

```bash
make deploy TARGET=root@192.168.1.100
# or:
scp build/06_GTK_Authentication_Demo root@192.168.1.100:/home/root/
```

Ensure GTK3 runtime is installed on the target:
```bash
ssh root@192.168.1.100 "apt-get install -y libgtk-3-0 || dnf install -y gtk3"
```

## Install on Target

```bash
ssh root@192.168.1.100 "systemctl enable --now se-daemon"
```

## Execute on Target

The target must have a display server running (Weston/Wayland or X11).

```bash
ssh root@192.168.1.100

# With Weston running:
WAYLAND_DISPLAY=wayland-1 ./06_GTK_Authentication_Demo          # /dev/i2c-1
WAYLAND_DISPLAY=wayland-1 ./06_GTK_Authentication_Demo 5        # /dev/i2c-5

# With X11:
DISPLAY=:0 ./06_GTK_Authentication_Demo 5
```

Or launch directly from the board's graphical console.

### Expected Behaviour

- A window opens with an **Authenticate** button.
- Press the button — a spinner appears while authentication runs in the background.
- On success the status label turns **green** and the log area shows all intermediate results.
- On failure the label turns **red** and the error step is highlighted.

## Troubleshooting

| Error | Action |
|-------|--------|
| `cannot open display` | Ensure `WAYLAND_DISPLAY` or `DISPLAY` environment variable is set |
| GTK3 library not found | Install GTK3 runtime on target: `libgtk-3-0` |
| Authentication FAIL — certificate | Ensure STSAFE-A120 carries the SPL05 CA certificate |
| `stse_init ERROR` | Check I²C bus and `se-daemon` |
| Build skipped silently | `pkg-config gtk+-3.0` not found in SDK sysroot |
