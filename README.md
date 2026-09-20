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
│   └── report.rs         # parse_tdreport: TDREPORT -> human readable JSON
├── kmod/
│   ├── tdx_verify.c      # ring-0 TDCALL[TDG.MR.VERIFYREPORT] (leaf 22)
│   ├── tdx_verify_uapi.h # userspace ABI of /dev/tdx_verify
│   └── Makefile          # build / load / unload the module
└── tests/
    ├── test_tdx_hardware.c   # C hardware test for both devices
    ├── test_tdx_hardware     # compiled test binary
    └── test_web_curl.sh      # end-to-end curl test of the running service
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
