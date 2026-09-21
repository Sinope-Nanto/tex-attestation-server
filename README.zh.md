# TDX 远程证明 Web 服务

一个使用 **Rust** 与 **[Rocket 0.5](https://rocket.rs)** 编写的小型 HTTP 服务，
对外暴露 TDX 远程证明流程所需的操作：*生成 TD 报告*、*校验 TD 报告*、
*解析 TD 报告*，以及一个存活探针。

所有证明操作都直接与**真实的 TDX 硬件**交互：

* 报告生成使用上游 guest 驱动 `/dev/tdx_guest`（`TDX_CMD_GET_REPORT0` →
  `TDCALL[TDG.MR.REPORT]`）；
* 报告校验使用辅助内核模块 `/dev/tdx_verify`（`TDX_VERIFY_REPORT` →
  `TDCALL[TDG.MR.VERIFYREPORT]`，TDX module leaf 22），这是**唯一**能够在本地
  证明报告确实由 TDX module 产生的操作。

报告绝不会被伪造，也绝不会在没有经过上述硬件校验的情况下被标记为可信。

---

## 接口一览

| 方法   | 路径                                        | 成功响应                | 客户端错误        | 不可用 |
|--------|---------------------------------------------|-------------------------|-------------------|--------|
| `GET`  | `/ping`                                     | `200 pong`              | –                 | –      |
| `GET`  | `/attestation-with-randomnumber?rn=<hex>`   | `200 {"report":"<hex>"}` | `400 Bad Request` | `501`  |
| `POST` | `/verify-report`                            | `200 {"trusted":bool}`  | `400 Bad Request` | `501`  |
| `POST` | `/parse-report`                             | `200 { ...解析结果... }` | `400 Bad Request` | –      |
| `GET`  | `/information_tpm`                          | `200 { ...度量结果... }` | `400 Bad Request` | `501`  |
| `POST` | `/quote_tpm`                                | `200 { ...quote... }`   | `400 Bad Request` | `501`  |

后两行是 **TPM** 接口，详见 [TPM 模拟器远程证明](#tpm-模拟器远程证明)。

所有错误响应共用同一个 JSON 信封：

```json
{ "error": "人类可读的错误原因" }
```

### 1. `GET /ping`

存活探针。始终返回 `200 OK`，纯文本响应体为 `pong`。

### 2. `GET /attestation-with-randomnumber?rn=<hex>`

* `rn` 是报告需要绑定的随机数（nonce），以 **十六进制** 编码。
* 处理函数会校验十六进制、解码为 `Vec<u8>`，然后调用 `generate_tdx_report()`。
* 较短的 nonce 会被零填充到固定的 64 字节 `REPORTDATA`；超过 64 字节则返回 `400`。

```console
$ curl -i "http://127.0.0.1:8080/attestation-with-randomnumber?rn=deadbeef"
HTTP/1.1 200 OK
{"report":"<2048 个十六进制字符，即 1024 字节的 TDREPORT>"}
```

返回的报告是真实的 `TDREPORT`（1024 字节），其中 `REPORTDATA` 位于偏移 `0x80`。

### 3. `POST /verify-report`

请求体：

```json
{ "report": "<tdx-report-hex>" }
```

处理函数解析 JSON、校验十六进制、解码后调用 `verify_tdx_report()`，
后者通过 `/dev/tdx_verify` 执行 `TDCALL[TDG.MR.VERIFYREPORT]`。

```console
$ curl -i -X POST -H "Content-Type: application/json" \
       -d '{"report":"<hex>"}' http://127.0.0.1:8080/verify-report
HTTP/1.1 200 OK
{"trusted":true}     # 未被篡改的报告
{"trusted":false}    # 被篡改的报告
```

### 4. `POST /parse-report`

请求体：

```json
{ "report": "<tdx-report-hex>" }
```

处理函数把十六进制的 `TDREPORT` 解析为**人类易读的 JSON**，字段含义与
Intel TDX Module ABI 中的 `TDREPORT_STRUCT` 一一对应。

> **注意**：这是一个纯粹的*解析*接口，它**不会**校验报告，也**不会**声称报告可信。
> 需要判断报告是否真实，请使用 `POST /verify-report`。

```console
$ curl -sS -X POST -H "Content-Type: application/json" \
       -d '{"report":"<hex>"}' http://127.0.0.1:8080/parse-report | jq .
{
  "report_len": 1024,
  "report_mac_struct": {
    "report_data": "6109df7f...（64 字节，十六进制）",
    "mac": "6fcd00d7...（32 字节，十六进制）"
  },
  "tee_tcb_info": {
    "valid": 197119,
    "tee_tcb_svn": "06010200...",
    "mrseam": "5b38e33a...",
    "mrsignerseam": "00000000...",
    "seamattributes": 0,
    "tdattributes": 131334,
    "xfd": 0
  },
  "tdinfo": {
    "attributes": 268435456,
    "xfam": 393959,
    "mrtd": "3da9a34f...",
    "mrconfigid": "00000000...",
    "mrowner": "00000000...",
    "mrownerconfig": "00000000...",
    "rtmr0": "72d8cfe7...",
    "rtmr1": "71171d38...",
    "rtmr2": "1e84df88...",
    "rtmr3": "00000000...",
    "servtd_hash": "00000000..."
  }
}
```

字段说明：

| 字段                              | 含义                                                       |
|-----------------------------------|------------------------------------------------------------|
| `report_len`                      | 报告字节长度，恒为 `1024`。                                |
| `report_mac_struct.report_data`   | `REPORTDATA`，报告绑定的 64 字节 nonce（十六进制）。       |
| `report_mac_struct.mac`           | `MAC`，覆盖 `REPORTMACSTRUCT` 的 32 字节 MAC（十六进制）。 |
| `tee_tcb_info.valid`              | `VALID`，指示下列字段哪些有效的位掩码。                    |
| `tee_tcb_info.tee_tcb_svn`        | `TEE_TCB_SVN`，TCB 安全版本号（十六进制）。                |
| `tee_tcb_info.mrseam`             | `MRSEAM`，SEAM 模块度量值（十六进制）。                    |
| `tee_tcb_info.mrsignerseam`       | `MRSIGNERSEAM`，SEAM 模块签名者（十六进制）。              |
| `tee_tcb_info.seamattributes`     | `SEAMATTRIBUTES`，SEAM 模块属性。                          |
| `tee_tcb_info.tdattributes`       | `TDATTRIBUTES`，TD 属性。                                  |
| `tee_tcb_info.xfd`                | `XFD`，被禁用的扩展特性位图。                              |
| `tdinfo.attributes`               | `ATTRIBUTES`，TD 属性。                                    |
| `tdinfo.xfam`                     | `XFAM`，可用的扩展特性位图。                               |
| `tdinfo.mrtd`                     | `MRTD`，TD 初始度量值（48 字节，十六进制）。               |
| `tdinfo.mrconfigid`               | `MRCONFIGID`，TD 配置度量值（48 字节，十六进制）。         |
| `tdinfo.mrowner`                  | `MROWNER`，TD 所有者度量值（48 字节，十六进制）。          |
| `tdinfo.mrownerconfig`            | `MROWNERCONFIG`，TD 所有者配置度量值（48 字节，十六进制）。|
| `tdinfo.rtmr0`..`rtmr3`           | `RTMR0`..`RTMR3`，运行时度量寄存器（48 字节，十六进制）。  |
| `tdinfo.servtd_hash`              | `SERVTD_HASH`，服务 TD 哈希（48 字节，十六进制）。         |

错误情况：

* 请求体不是合法 JSON → `400 Bad Request`；
* `report` 不是合法十六进制 → `400 Bad Request`；
* `report` 解码后不是 1024 字节 → `400 Bad Request`。

---

## 校验是如何工作的（以及为什么需要辅助内核模块）

上游内核驱动**刻意不暴露**执行 `TDCALL[TDG.MR.VERIFYREPORT]` 的途径。
该 leaf 是唯一能在本地建立真实性的操作：TDX module 使用自己持有的密钥
重新计算 `REPORTMACSTRUCT` 上的 MAC，并与报告携带的 MAC 比较。
以下两点排除了所有捷径：

* `TDCALL` 是 CPL0 指令——在 ring 3 执行会触发 `#GP`，因此任何用户态技巧都无法触达它；
* 重新计算报告哈希（对 `TEE_TCB_INFO` / `TDINFO` 做 `SHA384`）、检查 `REPORTDATA`、
  或断言 `reserved == 0` 都只是**结构性一致性检查**。任何伪造报告的人都能重新算出这些哈希，
  因此它们无法证明真实性。

因此 `tdx_verify` 内核模块（`kmod/`）只做一件事：在 ring 0 执行 leaf 22，
并把原始返回码交回用户态。`TDX_SUCCESS`（0）表示 TDX module 确认了 MAC；
其他任何值都表示未通过。校验器**绝不**退化为软件哈希比较；
如果 `/dev/tdx_verify` 不存在，它会返回 `501 Not Implemented`——绝不会返回 `Ok(true)`。

---

## 项目结构

```
workspace/
├── Cargo.toml            # Rocket 0.5（json feature）、serde、serde_json、hex、libc
├── Cargo.lock
├── Makefile              # 构建 + 测试入口
├── README.md             # 英文说明
├── README.zh.md          # 中文说明（本文件）
├── .gitignore
├── src/
│   ├── main.rs           # #[rocket::launch] 入口
│   ├── lib.rs            # pub fn rocket() -> Rocket<Build>，重新导出
│   ├── api.rs            # 路由、请求/响应体、ApiError、JSON catchers、单元测试
│   ├── attestation.rs    # generate_tdx_report / verify_tdx_report（含硬件校验）
│   ├── report.rs         # parse_tdreport：把 TDREPORT 解析为人类易读的 JSON
│   ├── logging.rs        # 基于文件的审计日志：请求、响应、错误、panic
│   └── tpm.rs            # TPM 2.0 后端：目录度量、PCR、quote
├── examples/
│   └── measure_folder.rs # 命令行工具：打印某个目录的度量摘要
├── kmod/
│   ├── tdx_verify.c      # ring-0 的 TDCALL[TDG.MR.VERIFYREPORT]（leaf 22）
│   ├── tdx_verify_uapi.h # /dev/tdx_verify 的用户态 ABI
│   └── Makefile          # 构建 / 加载 / 卸载内核模块
├── tpm-simu/             # Microsoft / TCG TPM 2.0 参考模拟器部署
└── tests/
    ├── test_tdx_hardware.c      # 两个设备的 C 硬件测试
    ├── test_tdx_hardware        # 编译后的测试二进制
    ├── test_web_curl.sh         # TDX 接口的端到端 curl 测试
    ├── test_tpm_integration.sh  # 真实模拟器：度量、PCR、quote、校验
    ├── test_tpm_web.sh          # TPM 接口的端到端 curl 测试
    └── test_logging.rs          # 审计日志：事件、错误引用、panic 捕获
```

### TDX 相关代码在哪里

所有需要真实 TDX 硬件的逻辑都集中在 **`src/attestation.rs`**：

| 函数                                              | 后端                                     |
|---------------------------------------------------|------------------------------------------|
| `generate_tdx_report(&[u8]) -> Result<Vec<u8>>`   | `/dev/tdx_guest`，`TDX_CMD_GET_REPORT0`  |
| `verify_tdx_report_hardware(&[u8]) -> Result<u64>`| `/dev/tdx_verify`，`TDG.MR.VERIFYREPORT` |
| `verify_tdx_report(&[u8]) -> Result<bool>`        | 上述函数的布尔包装                         |

纯解析逻辑位于 **`src/report.rs`**：

| 函数                                                       | 作用                              |
|------------------------------------------------------------|-----------------------------------|
| `parse_tdreport(&[u8]) -> Result<ParseReportResponse, _>`  | 把 1024 字节的 TDREPORT 解析为 JSON |

错误类型 `AttestationError` 有三个变体——`NotImplemented`、`InvalidInput`、
`Internal`——分别映射到 `501`、`400`、`500`。

---

## 运行

```console
cargo run
# 或：ROCKET_PORT=8080 ROCKET_ADDRESS=127.0.0.1 cargo run
```

服务默认端口是 Rocket 的 `8000`；测试脚本使用 `8080`。可通过 `ROCKET_PORT` 覆盖。

---

## 日志

除 Rocket 输出到控制台的日志外，服务还会在项目目录下维护一份基于文件的**审计日志**，
记录事后排查所需的必要信息：

* 每个 HTTP **请求**（方法、URI、客户端 IP）；
* 每个**响应**（方法、URI、状态码、耗时毫秒数）；
* 服务返回的每个**错误**，包含可读的原因（响应 fairing 只能看到状态码，
  因此原因在错误产生处记录）；
* 每次 **panic** —— panic hook 会在进程退出前记录线程、源码位置与消息，
  使意外崩溃可被事后诊断。

每行一个事件，采用 `key=value` 形式，既便于阅读也便于 grep：

```text
2024-01-01T00:00:00Z INFO  event=request method=GET uri=/ping client=127.0.0.1
2024-01-01T00:00:00Z INFO  event=response method=GET uri=/ping status=200 latency_ms=0
2024-01-01T00:00:00Z ERROR event=error method=POST uri=/verify-report status=400 message="..."
2024-01-01T00:00:00Z ERROR event=panic thread=main location=src/api.rs:1:1 message="..."
```

日志默认位于 `log/tdx-attestation.log`，可通过环境变量重定向：

| 变量           | 默认值                            | 含义             |
|----------------|-----------------------------------|------------------|
| `TDX_LOG_DIR`  | `<项目>/log`                      | 日志文件所在目录 |
| `TDX_LOG_FILE` | `<TDX_LOG_DIR>/tdx-attestation.log` | 日志文件完整路径 |

日志是尽力而为的：若文件无法打开，服务仍会继续运行，日志退化为空操作 ——
日志绝不能成为请求失败的原因。实现位于 [`src/logging.rs`](src/logging.rs)，
由 [`tests/test_logging.rs`](tests/test_logging.rs) 覆盖。

## 测试

```console
make test          # 硬件测试 + cargo 单元测试 + curl Web 测试
```

或分别执行：

```console
make test-hw       # ./tests/test_tdx_hardware   （需要真实的 /dev/tdx_guest + /dev/tdx_verify）
make test-unit     # cargo test
make test-web      # WEB_BASE_URL=http://127.0.0.1:8080 bash tests/test_web_curl.sh
make test-tpm      # 真实 TPM 模拟器：度量 + PCR + quote + 校验
make test-tpm-web  # TPM 接口的端到端 curl 测试
```

硬件测试会针对真实 TDX module 断言：

* 新生成的报告为 1024 字节，并回显 64 字节的 `REPORTDATA`；
* `TDCALL[TDG.MR.VERIFYREPORT]` 对它返回 `TDX_SUCCESS`；
* 在 `REPORTMACSTRUCT.REPORTDATA` 或 MAC 本身翻转一个比特都会被拒绝
  （返回码 `0xc000100100000000`，即 "MAC verification failed"）；
* 针对不同 nonce 的第二个报告同样能通过校验。

校验需要 `kmod` 辅助内核模块：

```console
make kmod-load     # 构建 + insmod；创建 /dev/tdx_verify
make -C kmod unload
```

---

## TPM 模拟器远程证明

除了 TDX 接口，服务还提供同样风格的、由 **TPM 2.0** 支撑的远程证明。
这里使用的设备是本仓库自带的 Microsoft / TCG 参考模拟器，因此整个流程——
目录度量、PCR extend、TPM quote——都可以在没有物理 TPM 的机器上端到端运行。

所有 TPM 相关代码都在 **`src/tpm.rs`**，它不会影响 TDX 路由：
TPM 的失败只会以 `501`/`500` 出现在 `*_tpm` 接口上。

### 后端如何与 TPM 通信

后端通过调用 **`tpm2-tools`** 与 TPM 交互——这正是参考实现 `gpu-node` 使用的方式——
并显式指定 TCTI，由部署决定访问哪一个 TPM：

```text
TCTI = mssim:host=127.0.0.1,port=2321      # 默认指向模拟器
```

TPM 是**有状态**设备，因此整个 `PCR_Reset` → `PCR_Extend` → `PCR_Read` → `Quote`
序列都在同一个进程级互斥锁（`tpm::TpmState`）下执行。并发 HTTP 请求会被串行化，
不会互相破坏 PCR 状态；并且 PCR **在 extend 之前总是先 reset**，
这保证了同一目录的重复度量是确定性的。

### 目录度量

参考实现 `gpu-node` 使用 SM3 度量一份**配置好的文件列表**。
本模拟器没有 SM3 bank，无法完全复刻该方案，因此这里改用下面这个完全确定的
目录遍历算法（即 `measure_folder()` 的实现）：

1. 递归遍历配置的目录；
2. 只度量**普通文件**（目录、FIFO、socket、设备文件都会被跳过）；
3. 只有当符号链接解析到**度量根目录内部**的普通文件时才会被跟随；
   指向外部的、或悬空的链接一律跳过；
4. 每个文件用**相对于度量根目录**的路径命名，分隔符统一为 `/`；
   由于路径由遍历本身产生，绝不可能包含 `..`；
5. `file_hash = SHA-256(文件内容)`；
6. 按相对路径的原始字节做字典序排序；
7. `total_hash = SHA-256( 按顺序对每个文件：
     u64_le(相对路径长度) || 相对路径 || file_hash )`。

因此 `total_hash` 同时绑定了每个文件的**相对路径**和**内容**。
同一目录度量两次结果相同；任何一个文件改动一个字节、或被重命名，结果都会不同。

> 目录摘要**不是**远程证明结果。它只是被 extend 进 PCR 的值；
> 真正的证明是 PCR 值加上 TPM 签名的 quote，二者都由 TPM 自己产生。

### 配置

代码里没有硬编码：由部署方设置以下环境变量（全部可选）。

| 环境变量             | 默认值                                        | 含义                                   |
|----------------------|-----------------------------------------------|----------------------------------------|
| `TPM_MEASURE_DIR`    | `<项目>/src`                                  | 要度量的目录                           |
| `TPM_PCR_INDEX`      | `16`                                          | 用于 reset/extend/quote 的 PCR         |
| `TPM_HASH_ALGORITHM` | `sha256`                                      | 哈希 bank（`sha1`、`sha256`、`sha384`）|
| `TPM_TCTI`           | `mssim:host=127.0.0.1,port=2321`              | 传给每个 `tpm2-*` 命令的 TCTI          |
| `TPM_AK_HANDLE`      | `0x81010002`                                  | 持久化 Attestation Key 的句柄          |
| `TPM_SIMULATOR_DIR`  | `tpm-simu`                                    | 模拟器部署目录（仅用于上报）           |

PCR `16` 是调试 PCR：可以从 locality 0 重置，正好满足确定性的
reset/extend 循环。`gpu-node` 使用同样的索引，`0x81010002` 也是它持久化的
Attestation Key 句柄（`gpu-node/src/tpm.h` 中的 `AK_HANDLE`），
因此已有部署可以无缝沿用。

### Attestation Key

已存在的 Key 会被**复用**。只有当配置的句柄上不存在 Key 时才会创建并持久化，
绝不会每个请求都创建：

```console
tpm2_createek -G rsa -c ek.ctx -u ek.pub
tpm2_createak -C ek.ctx -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pub
tpm2_evictcontrol -C o -c ak.ctx 0x81010002
```

公钥只读取一次并缓存（`tpm2_readpublic -f pem`）；每个 quote 都由 TPM 用该 Key 签名。

### `tpm-simu/` 中的模拟器

模拟器是 Microsoft / TCG TPM 2.0 参考实现的一份开箱即用部署，
本服务**不对其做任何修改**；构建方式见
[`tpm-simu/README.zh.md`](tpm-simu/README.zh.md)。

```console
$ ./tpm-simu/scripts/status.sh
RUNNING
  PID:            30369
  Listening ports: 2321 2322
  Command port (from state):  2321
  Platform port (from state): 2322
  Configured base port:       2321

$ ./tpm-simu/scripts/start.sh     # 启动（写入 tpm-simulator.pid）
$ ./tpm-simu/scripts/stop.sh      # 停止
$ ./tpm-simu/scripts/test.sh      # 模拟器自带的冒烟测试
```

| 服务             | 端口   | 用途                                        |
|------------------|--------|---------------------------------------------|
| TPM 命令端口     | `2321` | TPM 2.0 命令/响应流量                       |
| 平台端口         | `2322` | 平台信号（恒为命令端口 +1）                 |

### 接口

#### `GET /information_tpm`

度量配置的目录，把目录摘要 extend 进配置的 PCR，再读回该 PCR，返回上述全部信息。

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

* `measurement.total_hash` 即上面的目录摘要（第 7 步）。
* `pcr_value` 是 `PCR_Reset` + `PCR_Extend` 之后 `PCR_Read(pcr_index)` 的结果，
  十六进制编码。它永远不会等于 `total_hash`——extend 是哈希运算，不是复制。
* 只有成功读取 Attestation Key 时才会出现 `ak_pubkey`。

#### `POST /quote_tpm`

请求体字段名沿用 `gpu-node` 的 `/quote` 接口。`nonce` 是 challenge，
**十六进制编码**；`challenge` 可作为别名。`nonce_size` 与 `mask` 为兼容而接受，
但会被忽略（PCR 由服务端配置）。

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

* `evidence.tpm.signature` 是 TPM 真实产生的 `TPMT_SIGNATURE`，
  `evidence.tpm.message` 是它所覆盖的 `TPMS_ATTEST`。二者都编码为
  `base64(hex(bytes))`，而 `evidence.tpm.quote` 是把三个 blob 用 `:` 拼接——
  与 `gpu-node` 完全一致的线上格式。
* challenge 位于**被签名的结构内部**（`TPMS_ATTEST.extraData`），
  这正是 quote 与某次具体请求绑定的方式。
* `status` 使用 `gpu-node` 的状态码：`0` 成功、`9001` 度量失败、`9002` 请求错误、
  `9003` quote 失败。HTTP 层错误则使用统一的 `{"error":"..."}` 信封。

#### 校验 quote

返回的 `ak_pubkey` 与两个 blob 足以用 `tpm2_checkquote` 校验签名，
不需要服务端额外支持：

```console
# 先把 base64(hex(..)) 解码回原始字节，再校验
$ tpm2_checkquote -u ak.pem -g sha256 -m quote.msg -s quote.sig -q "$NONCE"
```

`tests/test_tpm_web.sh` 正是这么做的：它会拒绝伪造的 quote，
也会拒绝把 quote 与**错误** challenge 一起提交。

### 运行

```console
# 1. 启动模拟器
./tpm-simu/scripts/start.sh

# 2. 启动服务（TPM_MEASURE_DIR 默认为 ./src）
cargo run
```

### 测试

```console
make test-tpm       # 真实模拟器：度量、PCR reset/extend/read、quote、校验
make test-tpm-web   # /information_tpm 与 /quote_tpm 的 curl 端到端测试
```

`tests/test_tpm_integration.sh` 会在模拟器未运行时自动启动它，运行模拟器自带的
冒烟测试，然后度量真实目录、extend 真实 PCR、读回、产生真实 quote，
并用 Attestation Key 校验它。它使用服务端自己的实现来计算目录摘要
（`cargo run --example measure_folder -- <dir>`），因此 shell 测试不会与 Rust 代码脱节。

`tests/test_tpm_web.sh` 用 `curl` 驱动**运行中的**服务，检查内容包括：

* `/information_tpm` 返回 32 字节目录摘要、非零 PCR 值，且 PCR 值不等于目录摘要；
* 连续两次度量结果一致（PCR 是 reset 而不是累加）；
* `/quote_tpm` 返回非空的 signature 与 message，challenge 被回显并绑定进 `TPMS_ATTEST`；
* `tpm2_checkquote` 对正确 challenge 通过，对**错误** challenge 失败；
* 6 个并发请求全部成功，且目录摘要与 PCR 值一致（事务锁生效）；
* 不同 challenge 产生不同签名；
* 所有畸形请求（`{}`、`{"nonce":""}`、`{"nonce":"nothex"}`、
  `{"nonce":"abc"}`、65 字节 nonce、`nonce`/`challenge` 冲突、非 JSON body）
  都返回带 `{"error":...}` 信封的 `400`；
* 原有 TDX 接口（`/ping`、`/attestation-with-randomnumber`、`/verify-report`、
  `/parse-report`）行为不变。

### 故障排查

| 现象 | 原因 / 处理 |
|------|-------------|
| `*_tpm` 接口返回 `501` | 模拟器没在运行，或 `TPM_TCTI` 指向了错误的端口。检查 `./tpm-simu/scripts/status.sh` 与 `state/command.port`。 |
| `500`，信息含 `tpm2_pcrreset failed` | 该 PCR 不可重置。PCR `16` 可以；若配置了其他索引，请选择属于调试/可重置组的 PCR。 |
| `500`，信息含 `out of memory for object contexts` | 模拟器的瞬态对象槽位很少，之前的客户端留下了未释放的 context。反复执行 `tpm2_flushcontext -t` 可释放；服务在每次 quote 前都会 flush。 |
| `500`，信息含 `not initialized by TPM2_Startup` | 模拟器被重启了。服务在每次度量前都会调用 `tpm2_startup -c`，正常情况下不会看到；若出现请重启服务。 |
| `/quote_tpm` 返回 `400` | challenge 缺失、为空、非十六进制、长度为奇数，或超过 64 字节（`TPM2B_DATA` 限制）。 |
| `make test-tpm-web` 报 `501` | Web 测试自己会启动服务，但假定模拟器已运行；请先执行 `./tpm-simu/scripts/start.sh`。 |
