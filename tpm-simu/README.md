# TPM 2.0 Simulator

A self-contained deployment of the **Microsoft / TCG TPM 2.0 Reference
Implementation simulator** (`tpm2-simulator`).

## Overview

This directory contains a ready-to-run build of the TPM 2.0 simulator that
ships with the official TCG reference implementation maintained by Microsoft.
The simulator emulates a TPM 2.0 device and exposes it over a custom TCP
protocol, so that TSS stacks (e.g. `tpm2-tss` / `tpm2-tools`) and other
clients can talk to it exactly as they would to a real TPM.

The simulator implements two TCP services:

| Service            | Default port | Purpose                                              |
|--------------------|--------------|------------------------------------------------------|
| TPM command port   | `2321`       | TPM 2.0 command/response traffic                     |
| Platform port      | `2322`       | Platform signals (power on/off, reset, NV, PP, ...)  |

The platform port is always `command port + 1`.

## Source

The binary in `bin/` was built from the local source tree at:

```
../../ms-tpm-20-ref
```

Source revision (git):

```
commit ee21db0a941decd3cac67925ea3310873af60ab3
Date:   2024-10-04 11:12:27 -0700
```

## Build Environment

| Item            | Value                                                       |
|-----------------|-------------------------------------------------------------|
| OS              | Ubuntu 24.04.4 LTS (Noble Numbat)                           |
| Kernel          | Linux 6.8.0-137-generic, x86_64                             |
| Compiler        | gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0                 |
| Make            | GNU Make 4.3                                                |
| OpenSSL         | OpenSSL 3.0.13 30 Jan 2024 (library `libcrypto.so.3`)       |
| Autotools       | autoconf, automake, autoreconf, libtool                     |
| Other           | pkg-config 1.8.1, autoconf-archive, libssl-dev              |

## Directory Layout

```
tpm-simu/
├── bin/
│   └── tpm2-simulator        # the compiled simulator binary
├── scripts/
│   ├── start.sh              # start the simulator in the background
│   ├── stop.sh               # stop the simulator
│   ├── status.sh             # report RUNNING / STOPPED
│   └── test.sh               # end-to-end smoke test
├── state/                    # runtime state (NVChip, port files)
│   ├── NVChip                # persistent NV storage image
│   ├── command.port          # actual command port chosen by the simulator
│   └── platform.port         # actual platform port chosen by the simulator
├── logs/
│   └── tpm-simulator.log     # stdout/stderr of the simulator
├── tpm-simulator.pid         # PID of the running simulator (created at start)
├── README.md                 # this file
└── README.zh.md              # Chinese version
```

## Build Process

The following commands were actually executed to produce `bin/tpm2-simulator`:

```bash
# 1. Install build dependencies (only the ones that were missing)
apt-get update
apt-get install -y autoconf automake autoconf-archive libtool libssl-dev

# 2. Bootstrap the autotools build system
cd ms-tpm-20-ref/TPMCmd
./bootstrap

# 3. Configure
./configure

# 4. Build
make -j$(nproc)
```

The resulting binary is produced at:

```
ms-tpm-20-ref/TPMCmd/Simulator/src/tpm2-simulator
```

It was then copied to `bin/tpm2-simulator` in this deployment directory.

## Start

```bash
./scripts/start.sh
```

This launches the simulator in the background, writes its PID to
`tpm-simulator.pid`, and stores all runtime state under `state/`.

Environment variables:

| Variable        | Default | Meaning                                              |
|-----------------|---------|------------------------------------------------------|
| `TPM_SIM_PORT`  | `2321`  | Base TCP port (platform port is `+1`)                |
| `TPM_SIM_ARGS`  | (empty) | Extra arguments, e.g. `-m` to force re-manufacture   |

Example with a custom port:

```bash
TPM_SIM_PORT=3000 ./scripts/start.sh
```

## Stop

```bash
./scripts/stop.sh
```

Sends `SIGTERM`, waits for the process to exit, and removes the PID file.
If the process does not exit within 10 seconds it is killed with `SIGKILL`.

## Status

```bash
./scripts/status.sh
```

Prints `RUNNING` or `STOPPED`. When running, it also reports the PID and the
actual listening ports.

## Test

```bash
./scripts/test.sh
```

Runs the full smoke test suite:

1. binary exists and is executable
2. `start.sh` brings the simulator up
3. the TCP command port is actually listening
4. a real TPM command round-trip (`tpm2_getrandom` / `tpm2_getcap` via
   `tpm2-tools`, or a raw `TPM2_GetCapability` over the simulator protocol)
5. restart (`stop` + `start` + `status`) works
6. the simulator is left in the `RUNNING` state

## Network Interface

The simulator binds to **all interfaces** (`0.0.0.0`) on the configured ports.
There is no option in this implementation to restrict the bind address.

| Protocol | Address   | Port (default) | Purpose            |
|----------|-----------|----------------|--------------------|
| TCP      | 0.0.0.0   | 2321           | TPM command port   |
| TCP      | 0.0.0.0   | 2322           | Platform port      |

## TPM Client Usage

This deployment was verified with `tpm2-tools` (installed from the Ubuntu
repositories) using the `mssim` TCTI:

```bash
export TPM2TOOLS_TCTI="mssim:host=127.0.0.1,port=2321"

# Power-on / startup (required once after the simulator starts)
tpm2_startup -c

# Non-destructive smoke tests
tpm2_getrandom 8
tpm2_getcap properties-fixed
```

Both commands were executed successfully against this deployment and returned
valid TPM responses.

If you do not have `tpm2-tools`, any TSS stack that supports the Microsoft
simulator protocol (`mssim`) can connect to `127.0.0.1:2321`. The simulator
speaks the standard Microsoft simulator TCP protocol documented in
`TPMCmd/Simulator/include/TpmTcpProtocol.h`.

## State

All persistent state is stored in `state/`:

- `NVChip` — the TPM's NV storage image. This file is created on first start
  and updated as the TPM writes NV data. Deleting it forces the TPM to be
  re-manufactured on the next start.
- `command.port` / `platform.port` — the actual ports the simulator bound to.
  These are useful when `--pick_ports` is used and the requested port was
  already taken.

The simulator is started with its working directory set to `state/`, so all
of these files are written there rather than into the deployment root.

## Logs

Simulator stdout/stderr is appended to:

```
logs/tpm-simulator.log
```

## Troubleshooting

### Port already in use

If `start.sh` reports that the port is already in use, either stop the process
holding the port or start the simulator on a different port:

```bash
TPM_SIM_PORT=3000 ./scripts/start.sh
```

You can also pass `-p` (pick ports) via `TPM_SIM_ARGS` to let the simulator
choose the next free port automatically. In that case, read the actual port
from `state/command.port`.

### OpenSSL build issues

The build requires `libssl-dev` and a supported OpenSSL version. On Ubuntu:

```bash
apt-get install -y libssl-dev
```

If you see errors about deprecated OpenSSL 3.0 APIs, note that the build
already passes `-Wno-error=deprecated-declarations`; do not remove it.

### Stale PID file

If `tpm-simulator.pid` exists but the process is gone, `stop.sh` and
`start.sh` will detect this and remove the stale file automatically. You can
also delete it manually:

```bash
rm -f tpm-simulator.pid
```

### Missing build dependencies

If `./bootstrap` fails, install the autotools packages:

```bash
apt-get install -y autoconf automake autoconf-archive libtool pkg-config
```

## Security Notice

This is a **software TPM simulator**. It is intended for:

- development
- testing
- education
- protocol experiments

It does **not** provide the hardware security properties of a physical TPM.
Keys and secrets handled by the simulator are not protected by any hardware
root of trust, and the simulator should never be used to protect real
production secrets.
