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
│   └── report.rs         # parse_tdreport：把 TDREPORT 解析为人类易读的 JSON
├── kmod/
│   ├── tdx_verify.c      # ring-0 的 TDCALL[TDG.MR.VERIFYREPORT]（leaf 22）
│   ├── tdx_verify_uapi.h # /dev/tdx_verify 的用户态 ABI
│   └── Makefile          # 构建 / 加载 / 卸载内核模块
└── tests/
    ├── test_tdx_hardware.c   # 两个设备的 C 硬件测试
    ├── test_tdx_hardware     # 编译后的测试二进制
    └── test_web_curl.sh      # 针对运行中服务的端到端 curl 测试
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

## 测试

```console
make test          # 硬件测试 + cargo 单元测试 + curl Web 测试
```

或分别执行：

```console
make test-hw       # ./tests/test_tdx_hardware   （需要真实的 /dev/tdx_guest + /dev/tdx_verify）
make test-unit     # cargo test
make test-web      # WEB_BASE_URL=http://127.0.0.1:8080 bash tests/test_web_curl.sh
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
