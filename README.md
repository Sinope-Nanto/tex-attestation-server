# TDX Attestation Web Service

A small HTTP service, written in **Rust** with **[Rocket 0.5](https://rocket.rs)**, that exposes the
operations a TDX attestation flow needs — *generate a TD report* and *verify a TD report* — plus a
liveness probe.

Both attestation operations talk to **real TDX hardware**:

* report generation uses the upstream guest driver `/dev/tdx_guest` (`TDX_CMD_GET_REPORT0` →
  `TDCALL[TDG.MR.REPORT]`);
* report verification uses the helper module `/dev/tdx_verify` (`TDX_VERIFY_REPORT` →
  `TDCALL[TDG.MR.VERIFYREPORT]`, TDX module leaf 22), which is the **only** local operation that
  can prove a report was produced by the TDX module.

A report is never fabricated and never reported as trusted without that hardware check.

---

## API

| Method | Path                                   | Success           | Client error      | Not available |
|--------|----------------------------------------|-------------------|-------------------|---------------|
| `GET`  | `/ping`                                | `200 pong`        | –                 | –             |
| `GET`  | `/attestation-with-randomnumber?rn=<hex>` | `200 {"report":"<hex>"}` | `400 Bad Request` | `501` |
| `POST` | `/verify-report`                       | `200 {"trusted":bool}` | `400 Bad Request` | `501` |
| `POST` | `/parse-report`                        | `200 { ...decoded... }` | `400 Bad Request` | – |
| `GET`  | `/information_tpm`                     | `200 { ...measurement... }` | `400 Bad Request` | `501` |
| `POST` | `/quote_tpm`                           | `200 { ...quote... }` | `400 Bad Request` | `501` |
| `POST` | `/attestation_all`                     | `200 { ...tpm+tdx... }` | `400 Bad Request` | `501` |
| `POST` | `/verify_all`                          | `200 {"trusted":bool,...}` | `400 Bad Request` | `501` |

The `/information_tpm` and `/quote_tpm` rows are the **TPM** endpoints; see
[TPM Simulator Attestation](#tpm-simulator-attestation). The last two rows are
the **combined** endpoints, which return and verify a TPM quote *and* a TDX
report bound to the same challenge; see
[Combined TPM + TDX attestation](#combined-tpm--tdx-attestation).

All error responses share one JSON envelope:

```json
{ "error": "human readable reason" }
```

### 1. `GET /ping`

Liveness probe. Always `200 OK` with the plain-text body `pong`.

### 2. `GET /attestation-with-randomnumber?rn=<hex>`

* `rn` is the **hex-encoded** random number (nonce) the report must be bound to.
* The handler validates the hex, decodes it to `Vec<u8>` and calls `generate_tdx_report()`.
* Shorter nonces are zero-padded to the fixed 64-byte `REPORTDATA`; longer ones are a `400`.

```console
$ curl -i "http://127.0.0.1:8080/attestation-with-randomnumber?rn=deadbeef"
HTTP/1.1 200 OK
{"report":"<2048 hex chars, 1024-byte TDREPORT>"}
```

The returned report is a genuine `TDREPORT` (1024 bytes) with `REPORTDATA` at offset `0x80`.

### 3. `POST /verify-report`

Request body:

```json
{ "report": "<tdx-report-hex>" }
```

The handler parses the JSON, validates the hex, decodes it and calls `verify_tdx_report()`, which runs
`TDCALL[TDG.MR.VERIFYREPORT]` through `/dev/tdx_verify`.

```console
$ curl -i -X POST -H "Content-Type: application/json" \
       -d '{"report":"<hex>"}' http://127.0.0.1:8080/verify-report
HTTP/1.1 200 OK
{"trusted":true}     # pristine report
{"trusted":false}    # tampered report
```

### 4. `POST /parse-report`

Request body:

```json
{ "report": "<tdx-report-hex>" }
```

Decodes a hex encoded `TDREPORT` into a **human readable JSON** document whose
fields mirror the Intel TDX Module ABI `TDREPORT_STRUCT`.

> This is a *parsing* endpoint only: it never verifies the report and never
> claims it is authentic. Use `POST /verify-report` for that.

```console
$ curl -sS -X POST -H "Content-Type: application/json" \
       -d '{"report":"<hex>"}' http://127.0.0.1:8080/parse-report | jq .
{
  "report_len": 1024,
  "report_mac_struct": { "report_data": "...", "mac": "..." },
  "tee_tcb_info": { "valid": 197119, "tee_tcb_svn": "...", "mrseam": "...",
                    "mrsignerseam": "...", "seamattributes": 0,
                    "tdattributes": 131334, "xfd": 0 },
  "tdinfo": { "attributes": 268435456, "xfam": 393959, "mrtd": "...",
              "mrconfigid": "...", "mrowner": "...", "mrownerconfig": "...",
              "rtmr0": "...", "rtmr1": "...", "rtmr2": "...", "rtmr3": "...",
              "servtd_hash": "..." }
}
```

Errors: malformed JSON, non-hex `report`, or a report that is not 1024 bytes
all yield `400 Bad Request`.

---

## How verification works (and why it needs a helper module)

The upstream kernel driver deliberately exposes **no** way to run
`TDCALL[TDG.MR.VERIFYREPORT]`. That leaf is the only *local* operation that establishes authenticity:
the TDX module recomputes the MAC over `REPORTMACSTRUCT` with the key it holds and compares it with
the MAC carried in the report. Two facts rule out every shortcut:

* `TDCALL` is a CPL0 instruction — from ring 3 it raises `#GP`, so no userspace trick can reach it;
* re-hashing the report (`SHA384` over `TEE_TCB_INFO` / `TDINFO`), checking `REPORTDATA`, or asserting
  `reserved == 0` are **structural consistency checks** only. Anyone fabricating a report can recompute
  those hashes, so they prove nothing about authenticity.

The `tdx_verify` kernel module (`kmod/`) therefore does exactly one thing: it runs leaf 22 in ring 0
and hands the raw return code back. `TDX_SUCCESS` (0) means the TDX module confirms the MAC;
anything else means it does not. The verifier **never** degrades into a software hash comparison, and
if `/dev/tdx_verify` is absent it returns `501 Not Implemented` — never `Ok(true)`.

---

## Project layout

```
workspace/
├── Cargo.toml            # Rocket 0.5 (json feature), serde, serde_json, hex, libc
├── Cargo.lock
├── Makefile              # build + test entry points
├── README.md             # English documentation
├── README.zh.md          # Chinese documentation
├── .gitignore
├── src/
│   ├── main.rs           # #[rocket::launch] entry point
│   ├── lib.rs            # pub fn rocket() -> Rocket<Build>, re-exports
│   ├── api.rs            # routes, payloads, ApiError, JSON catchers, unit tests
│   ├── attestation.rs    # generate_tdx_report / verify_tdx_report (+ hardware verify)
│   ├── report.rs         # parse_tdreport: TDREPORT -> human readable JSON
│   ├── logging.rs        # file based audit log: requests, responses, errors, panics
│   └── tpm.rs            # TPM 2.0 backend: folder measurement, PCR, quote
├── examples/
│   └── measure_folder.rs # CLI: prints the folder digest of a directory
├── kmod/
│   ├── tdx_verify.c      # ring-0 TDCALL[TDG.MR.VERIFYREPORT] (leaf 22)
│   ├── tdx_verify_uapi.h # userspace ABI of /dev/tdx_verify
│   └── Makefile          # build / load / unload the module
├── tpm-simu/             # Microsoft / TCG TPM 2.0 reference simulator deployment
└── tests/
    ├── test_tdx_hardware.c      # C hardware test for both devices
    ├── test_tdx_hardware        # compiled test binary
    ├── test_web_curl.sh         # end-to-end curl test of the TDX endpoints
    ├── test_tpm_integration.sh  # real simulator: measure, PCR, quote, verify
    ├── test_tpm_web.sh          # end-to-end curl test of the TPM + combined endpoints
    ├── test_attestation_all.rs  # combined /attestation_all + /verify_all validation
    └── test_logging.rs          # audit log: events, error quoting, panic capture
```

### Where the TDX work lives

Everything that needs real TDX hardware is confined to **`src/attestation.rs`**:

| Function                                        | Backend                                  |
|-------------------------------------------------|------------------------------------------|
| `generate_tdx_report(&[u8]) -> Result<Vec<u8>>` | `/dev/tdx_guest`, `TDX_CMD_GET_REPORT0`  |
| `verify_tdx_report_hardware(&[u8]) -> Result<u64>` | `/dev/tdx_verify`, `TDG.MR.VERIFYREPORT` |
| `verify_tdx_report(&[u8]) -> Result<bool>`      | thin boolean wrapper over the above      |

The error type `AttestationError` has three variants — `NotImplemented`, `InvalidInput`,
`Internal` — mapped to `501`, `400` and `500` respectively.

---

## Run

```console
cargo run
# or: ROCKET_PORT=8080 ROCKET_ADDRESS=127.0.0.1 cargo run
```

The server default port is Rocket's `8000`; the test harness uses `8080`. Override with `ROCKET_PORT`.

---

## Logging

The service keeps a file based **audit log** next to the console output Rocket
produces. It records the information an operator needs *after* something went
wrong:

* every HTTP **request** (method, URI, client IP);
* every **response** (method, URI, status code, latency in ms);
* every **error** the service answered with, including the human readable reason
  (the response fairing only sees the status code, so the reason is logged where
  the error is produced);
* every **panic** - the panic hook records the thread, source location and
  message before the process aborts, so an unexpected crash is diagnosable.

One event per line, `key=value` pairs, so the file is both human readable and
easy to grep:

```text
2024-01-01T00:00:00Z INFO  event=request method=GET uri=/ping client=127.0.0.1
2024-01-01T00:00:00Z INFO  event=response method=GET uri=/ping status=200 latency_ms=0
2024-01-01T00:00:00Z ERROR event=error method=POST uri=/verify-report status=400 message="..."
2024-01-01T00:00:00Z ERROR event=panic thread=main location=src/api.rs:1:1 message="..."
```

The log lives in `log/tdx-attestation.log` by default and can be redirected:

| Variable       | Default                          | Meaning                       |
|----------------|----------------------------------|-------------------------------|
| `TDX_LOG_DIR`  | `<project>/log`                  | directory the log file lives in |
| `TDX_LOG_FILE` | `<TDX_LOG_DIR>/tdx-attestation.log` | full path of the log file  |

Logging is best effort: if the file cannot be opened the service keeps running
and logging degrades to a no-op - logging must never be the reason a request
fails. The implementation is in [`src/logging.rs`](src/logging.rs) and is covered
by [`tests/test_logging.rs`](tests/test_logging.rs).

## Test

```console
make test          # hardware test + cargo unit tests + curl web test
```

or individually:

```console
make test-hw       # ./tests/test_tdx_hardware   (real /dev/tdx_guest + /dev/tdx_verify)
make test-unit     # cargo test
make test-web      # WEB_BASE_URL=http://127.0.0.1:8080 bash tests/test_web_curl.sh
```

The hardware test asserts, against the real TDX module:

* a fresh report is 1024 bytes and echoes the 64-byte `REPORTDATA`;
* `TDCALL[TDG.MR.VERIFYREPORT]` returns `TDX_SUCCESS` for it;
* a single bit flipped inside `REPORTMACSTRUCT.REPORTDATA` **or** in the MAC itself is rejected
  (return code `0xc000100100000000`, "MAC verification failed");
* a second report for a different nonce also verifies.

The `kmod` helper module is required for verification:

```console
make kmod-load     # build + insmod; creates /dev/tdx_verify
make -C kmod unload
```

---

## TPM Simulator Attestation

Next to the TDX endpoints, the service offers the same style of attestation
backed by a **TPM 2.0** device. The device used here is the Microsoft / TCG
reference simulator that ships with this repository, so the whole flow - folder
measurement, PCR extend, TPM quote - runs end to end without any physical TPM.

Everything TPM related lives in **`src/tpm.rs`**, and nothing in it can affect
the TDX routes: a TPM failure is reported as `501`/`500` on the `*_tpm` routes
only.

### How the backend talks to the TPM

The backend shells out to **`tpm2-tools`** - exactly the technique the reference
`gpu-node` service uses - with an explicit TCTI, so the deployment decides which
TPM is addressed:

```text
TCTI = mssim:host=127.0.0.1,port=2321      # the simulator, by default
```

A TPM is a **stateful** device, so the whole `PCR_Reset` → `PCR_Extend` →
`PCR_Read` → `Quote` sequence runs under one process-wide mutex
(`tpm::TpmState`). Concurrent HTTP requests are therefore serialised instead of
corrupting each other's PCR state, and the PCR is always **reset before it is
extended**, which keeps repeated measurements of the same directory
deterministic.

### Folder measurement

The reference `gpu-node` measures a *configured file list* with SM3. That exact
scheme cannot be reproduced here (this simulator has no SM3 bank), so the
deterministic directory walk below is used instead. It is fully specified, and
it is the algorithm `measure_folder()` implements:

1. the configured directory is walked recursively;
2. only **regular files** are measured (directories, FIFOs, sockets and devices
   are skipped);
3. a symlink is followed only when it resolves to a regular file **inside** the
   measured root - anything pointing outside, or dangling, is skipped;
4. every file is named by its path **relative to the measured root**, using `/`
   separators; a relative path can never contain `..` because it is derived from
   the walk itself;
5. `file_hash = SHA-256(file contents)`;
6. files are sorted by the raw bytes of their relative path (lexicographic);
7. `total_hash = SHA-256( for each file in order:
     u64_le(len(relative_path)) || relative_path || file_hash )`.

`total_hash` therefore binds both the **relative path** and the **contents** of
every file. Measuring the same directory twice yields the same digest; changing
a single byte of any measured file - or renaming one - yields a different one.

> The folder digest is **not** the attestation. It is only the value that gets
extended into the PCR; the attestation is the PCR value plus the signed quote,
both produced by the TPM itself.

### Configuration

Nothing is hardcoded in the code: the deployment sets these environment
variables (all optional).

| Variable             | Default                                       | Meaning                                |
|----------------------|-----------------------------------------------|----------------------------------------|
| `TPM_MEASURE_DIR`    | `<project>/src`                               | directory to measure                   |
| `TPM_PCR_INDEX`      | `16`                                          | PCR to reset/extend/quote              |
| `TPM_HASH_ALGORITHM` | `sha256`                                      | hash bank (`sha1`, `sha256`, `sha384`) |
| `TPM_TCTI`           | `mssim:host=127.0.0.1,port=2321`              | TCTI passed to every `tpm2-*` call     |
| `TPM_AK_HANDLE`      | `0x81010002`                                  | persistent Attestation Key handle      |
| `TPM_SIMULATOR_DIR`  | `tpm-simu`                                    | simulator deployment (reported only)   |

PCR `16` is a debug PCR: it is resettable from locality 0, which is exactly what
the deterministic reset/extend cycle needs. `gpu-node` uses the same index, and
`0x81010002` is the same Attestation Key handle it persists (`AK_HANDLE` in
`gpu-node/src/tpm.h`), so an existing deployment keeps working unchanged.

### Attestation Key

The key an existing deployment already has is **reused**. A new one is created
and persisted only when the configured handle is empty, and never per request:

```console
tpm2_createek -G rsa -c ek.ctx -u ek.pub
tpm2_createak -C ek.ctx -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pub
tpm2_evictcontrol -C o -c ak.ctx 0x81010002
```

The public part is read once and cached (`tpm2_readpublic -f pem`); every quote
is signed by the TPM with this key.

### The simulator in `tpm-simu/`

The simulator is a ready-to-run deployment of the Microsoft / TCG TPM 2.0
reference implementation. It is **not** modified by this service; see
[`tpm-simu/README.md`](tpm-simu/README.md) for how it was built.

```console
$ ./tpm-simu/scripts/status.sh
RUNNING
  PID:            30369
  Listening ports: 2321 2322
  Command port (from state):  2321
  Platform port (from state): 2322
  Configured base port:       2321

$ ./tpm-simu/scripts/start.sh     # start it (writes tpm-simulator.pid)
$ ./tpm-simu/scripts/stop.sh      # stop it
$ ./tpm-simu/scripts/test.sh      # the simulator's own smoke test
```

| Service          | Port   | Purpose                                            |
|------------------|--------|----------------------------------------------------|
| TPM command port | `2321` | TPM 2.0 command/response traffic                   |
| Platform port    | `2322` | platform signals (always `command port + 1`)       |

### API

#### `GET /information_tpm`

Measures the configured directory, extends the configured PCR with the folder
digest, reads the PCR back and returns all of it.

```console
$ curl -sS http://127.0.0.1:8080/information_tpm | jq .
{
  "backend": "tpm2-tools",
  "simulator": "tpm-simu",
  "tcti": "mssim:host=127.0.0.1,port=2321",
  "measured_directory": "/root/mhz/tdx-attestation-server/workspace/src",
  "hash_algorithm": "sha256",
  "pcr_index": 16,
  "measurement": {
    "time-stamp": "2026.09.21 08:04:47",
    "measurement": [
      { "name": "api.rs",   "hash": "32eb61fc...", "size": 11428 },
      { "name": "lib.rs",   "hash": "...",         "size": 3212 }
    ],
    "total_hash": "a5d1bccc00bda96a..."
  },
  "pcr_value": "9f2dbe6176c55a78...",
  "ak_handle": "0x81010002",
  "ak_pubkey": "-----BEGIN PUBLIC KEY-----\n..."
}
```

* `measurement.total_hash` is the folder digest (step 7 above).
* `pcr_value` is `PCR_Read(pcr_index)` **after** `PCR_Reset` + `PCR_Extend`, hex
  encoded. It is never equal to `total_hash` - the extend is a hash, not a copy.
* `ak_pubkey` is present only when the Attestation Key could be read.

#### `POST /quote_tpm`

Request body - the field names follow `gpu-node`'s `/quote` endpoint. `nonce`
is the challenge, **hex encoded**; `challenge` is accepted as an alias.
`nonce_size` and `mask` are accepted for compatibility and ignored (the PCR is
configured server side).

```json
{ "nonce": "f0e1d2c3...", "nonce_size": 32, "mask": "0000..." }
```

```console
$ NONCE=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
$ curl -sS -X POST -H 'Content-Type: application/json' \
       -d "{\"nonce\":\"$NONCE\"}" \
       http://127.0.0.1:8080/quote_tpm | jq .
{
  "status": 0,
  "measurement": { "time-stamp": "...", "measurement": [ ... ],
                   "total_hash": "a5d1bccc..." },
  "pcr_value": "9f2dbe61...",
  "pcr_index": 16,
  "hash_algorithm": "sha256",
  "evidence": {
    "tpm": {
      "quote": "<base64>:<base64>:<base64>",
      "quote_size": 2874,
      "signature": "<base64(hex(TPMT_SIGNATURE))>",
      "message": "<base64(hex(TPMS_ATTEST))>",
      "pcrs": "<base64(hex(TPML_PCR_SELECTION))>",
      "signature_size": 262,
      "message_size": 145,
      "nonce": "f0e1d2c3...",
      "nonce_size": 32,
      "pcr_index": 16,
      "hash_algorithm": "sha256",
      "ak_handle": "0x81010002"
    }
  },
  "ak_pubkey": "-----BEGIN PUBLIC KEY-----\n..."
}
```

* `evidence.tpm.signature` is the real `TPMT_SIGNATURE` produced by the TPM, and
  `evidence.tpm.message` is the `TPMS_ATTEST` it covers. Both are encoded as
  `base64(hex(bytes))`, and `evidence.tpm.quote` is the three blobs joined with
  `:` - the same wire format `gpu-node` emits.
* The challenge is **inside** the signed structure (`TPMS_ATTEST.extraData`),
  which is what binds a quote to a particular request.
* `status` uses the `gpu-node` codes: `0` success, `9001` measure failure,
  `9002` request error, `9003` quote failure. On an HTTP error the response uses
  the shared `{"error":"..."}` envelope instead.

#### Verifying a quote

The returned `ak_pubkey` and the two blobs are enough to check the signature with
`tpm2_checkquote` - no extra server support needed:

```console
# decode base64(hex(..)) back to raw bytes, then verify
$ tpm2_checkquote -u ak.pem -g sha256 -m quote.msg -s quote.sig -q "$NONCE"
```

This is exactly what `tests/test_tpm_web.sh` does: it rejects a fabricated quote
and rejects a quote presented together with the *wrong* challenge.

---

## Combined TPM + TDX attestation

The two attestation backends can be used **together**: `POST /attestation_all`
returns the `/quote_tpm` structure with an extra `evidence.tdx` block, and
`POST /verify_all` takes that exact structure back and verifies both halves.

Both halves are bound to the **same challenge**, so a verifier can check that a
single nonce was attested by the TPM *and* by the TDX module.

### `POST /attestation_all`

Request body: identical to `/quote_tpm` (`nonce` / `challenge`, hex encoded).

```console
$ NONCE=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
$ curl -sS -X POST -H 'Content-Type: application/json' \
       -d "{\"nonce\":\"$NONCE\"}" \
       http://127.0.0.1:8080/attestation_all | jq .
{
  "status": 0,
  "measurement": { ... },
  "pcr_value": "9f2dbe61...",
  "pcr_index": 16,
  "hash_algorithm": "sha256",
  "evidence": {
    "tpm": { ...same as /quote_tpm... },
    "tdx": {
      "report": "<2048 hex chars, 1024-byte TDREPORT>",
      "nonce": "f0e1d2c3...",
      "nonce_size": 32
    }
  },
  "ak_pubkey": "-----BEGIN PUBLIC KEY-----\n..."
}
```

* `evidence.tpm` is exactly what `/quote_tpm` returns.
* `evidence.tdx.report` is a genuine `TDREPORT` produced by the TDX module
  (`/dev/tdx_guest`), with `REPORTDATA` seeded from the same challenge.
* If **either** backend is unavailable the whole request answers `501` - the
  structure is never returned half-filled.

### `POST /verify_all`

Request body: the exact structure returned by `/attestation_all`.

```console
$ curl -sS -X POST -H 'Content-Type: application/json' \
       --data-binary @all.json \
       http://127.0.0.1:8080/verify_all | jq .
{
  "trusted": true,
  "tpm_trusted": true,
  "tdx_trusted": true
}
```

* `tdx_trusted` comes from the TDX module itself
  (`TDCALL[TDG.MR.VERIFYREPORT]`, see [How verification works](#how-verification-works-and-why-it-needs-a-helper-module)).
* `tpm_trusted` comes from `tpm2_checkquote`, run against the Attestation Key
  public part carried by the same structure.
* `trusted` is `true` only when **both** halves verify. A tampered TDX report or a
  tampered TPM signature yields `trusted=false` with the corresponding flag set
  to `false`.
* A structure without the `tdx` field, or with a non-hex report, is a
  `400 Bad Request` - never a silent `trusted=false`.

### Running

```console
# 1. the simulator
./tpm-simu/scripts/start.sh

# 2. the service (TPM_MEASURE_DIR defaults to ./src)
cargo run
```

### Testing

```console
make test-tpm       # real simulator: measure, PCR reset/extend/read, quote, verify
make test-tpm-web   # curl end-to-end test of /information_tpm and /quote_tpm
```

`tests/test_tpm_integration.sh` starts the simulator if it is not running, runs
the simulator's own smoke test, then measures a real directory, extends a real
PCR, reads it back, produces a real quote and verifies it against the
Attestation Key. It computes the folder digest with the server's own
implementation (`cargo run --example measure_folder -- <dir>`), so the shell
test cannot drift from the Rust code.

`tests/test_tpm_web.sh` drives a **running** service with `curl` and checks,
among other things:

* `/information_tpm` returns a 32-byte folder digest, a non-zero PCR value, and
  a PCR value that differs from the folder digest;
* two consecutive measurements agree (the PCR is reset, not accumulated);
* `/quote_tpm` returns a non-empty signature and message, and the challenge is
  echoed and bound into `TPMS_ATTEST`;
* `tpm2_checkquote` accepts the quote for the right challenge and **rejects** it
  for a wrong one;
* six concurrent requests all succeed and agree on the folder digest and PCR
  value (the transaction lock works);
* a different challenge produces a different signature;
* every malformed request (`{}`, `{"nonce":""}`, `{"nonce":"nothex"}`,
  `{"nonce":"abc"}`, a 65-byte nonce, conflicting `nonce`/`challenge`, a
  non-JSON body) is a `400` with the `{"error":...}` envelope;
* the original TDX endpoints (`/ping`, `/attestation-with-randomnumber`,
  `/verify-report`, `/parse-report`) still behave as before;
* `/attestation_all` returns both `evidence.tpm` and `evidence.tdx`, with the TDX
  report bound to the same challenge, and `/verify_all` accepts the structure
  (`trusted=true`), rejects a tampered TDX report (`tdx_trusted=false`) and
  answers `400` for a structure without the `tdx` field.

### Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `501` from a `*_tpm` route | The simulator is not running, or `TPM_TCTI` points at the wrong port. Check `./tpm-simu/scripts/status.sh` and `state/command.port`. |
| `500` with `tpm2_pcrreset failed` | The PCR is not resettable. PCR `16` is; if you configured another index, pick one that belongs to the debug/resettable group. |
| `500` with `out of memory for object contexts` | The simulator has very few transient object slots and an earlier client left contexts loaded. `tpm2_flushcontext -t` (repeatedly) releases them; the service flushes before every quote. |
| `500` with `not initialized by TPM2_Startup` | The simulator was restarted. The service calls `tpm2_startup -c` before every measurement, so this should not be visible; if it is, restart the service. |
| `400` on `/quote_tpm` | The challenge is missing, empty, not hex, odd-length, or longer than 64 bytes (`TPM2B_DATA` bound). |
| `make test-tpm-web` reports `501` | The web test starts the service itself but assumes the simulator is up; run `./tpm-simu/scripts/start.sh` first. |
