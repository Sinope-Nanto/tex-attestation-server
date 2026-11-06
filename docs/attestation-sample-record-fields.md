# 证明耗时样本（NDJSON）逐字段注释与度量指南

> 配套文档：[attestation-latency-measurement.md](attestation-latency-measurement.md)（流程与度量点清单 M01–M73）
>
> 本文以如下这条样本记录为**格式基准**：逐个字段解释"是什么、从哪来、怎么读"，
> 再给出"每个字段到底怎么测"的落地方案，供后续埋点与采集工作直接照做。
>
> ⚠️ 样本中的**数值仅用于说明字段形状**，不可当作性能基线 —— 原因见
> [§5 数值自洽性核对](#5-数值自洽性核对为什么示例数字不能当基线)。
>
> **不包含任何代码修改。**

---

## 0. 这份文档怎么用

| 你的任务 | 看哪一节 |
|----------|----------|
| 只想知道某个字段是什么意思 | §3 逐字段注释 |
| 要实现埋点、去哪个函数打点 | §4 每个字段怎么度量 |
| 拿到一堆样本要判断数据可信否 | §5 自洽性核对 |
| 要改 schema、加字段 | §6 schema 修订建议 |
| 排期、分工 | §7 后续工作清单 |
| 与主方案文档的对应关系 | §8 M 编号映射 |

---

## 1. 样本全貌（格式基准）

```json
{
  "ts": "2026-11-06T07:04:51Z",
  "route": "/attestation_all",
  "http_status": 200,
  "warm": true,
  "concurrency": 1,
  "e2e_server_us": 128400,
  "e2e_client_us": 131020,
  "stages": {
    "http_body_read_us": 120,
    "json_deserialize_us": 40,
    "nonce_validate_us": 3,
    "lock_wait_us": 12,
    "scratch_new_us": 60,
    "measure_and_extend_us": 41200,
    "ensure_ak_us": 18300,
    "create_quote_us": 62400,
    "tdx_report_us": 5310,
    "ak_pubkey_us": 2,
    "scratch_drop_us": 45,
    "serialize_us": 380
  },
  "units": {
    "measure_folder_us": 33800,
    "collect_regular_files_us": 2600,
    "read_and_hash_loop_us": 30900,
    "tpm2_startup_us": 18100,
    "tpm2_pcrreset_us": 17800,
    "tpm2_pcrextend_us": 18200,
    "tpm2_pcrread_us": 19500,
    "tpm2_getcap_us": 17900,
    "tpm2_flushcontext_us": 17500,
    "tpm2_quote_us": 25600,
    "ioctl_get_report_us": 5230,
    "files_measured": 6,
    "bytes_measured": 48213
  },
  "unattributed_us": -1288,
  "checksum_ok": true
}
```

**一条记录 = 一次 HTTP 请求**（一行 NDJSON），不是一次"证明"。
完整的"证明闭环"由**两条记录**拼成：`route=/attestation_all` 的那条 + `route=/verify_all` 的那条。

---

## 2. 字段分组总览

| 组 | 字段 | 数量 | 作用 | 是否可加 |
|----|------|------|------|----------|
| 元信息 | `ts` `route` `http_status` `warm` `concurrency` | 5 | 标识样本、决定能否与其他样本对比 | 否（维度） |
| 端到端 | `e2e_server_us` `e2e_client_us` | 2 | SLO 口径，两个视角 | 否（两个独立标量） |
| 阶段 | `stages.*` | 12 | `e2e_server` 的一级拆分，**互斥且应可加** | 是，≈ e2e_server |
| 单元 | `units.*` | 11 时长 + 2 计数 | 阶段内部再拆分，**扁平、可跨父级** | 按父级分组后可加 |
| 派生/校验 | `unattributed_us` `checksum_ok` | 2 | 未归因残差、样本可信标记 | 计算得出 |

三条硬规则（后续所有争论都回到这三条）：

1. **`stages` 互斥**：一次请求的每个瞬间只能落在一个 stage 里，否则不可加。
2. **`units` 用名字前缀表达父子**：`measure_folder_us` 属于 `measure_and_extend_us`，
   `ioctl_get_report_us` 属于 `tdx_report_us`；`units` 里混了"别处的量"就是 bug。
3. **计数不是时长**：`files_measured` / `bytes_measured` 没有 `_us` 后缀，不可求和进耗时。

---

## 3. 逐字段注释

### 3.1 元信息

| 字段 | 类型 | 含义 | 来源 | 判读要点 |
|------|------|------|------|----------|
| `ts` | string, RFC3339 UTC | 采样时刻 | 采样工具写入，**不要**用业务代码里的 `utc_timestamp()` | 秒级精度不够：同一秒内的多条样本要能区分 → 建议升到毫秒（`2026-11-06T07:04:51.237Z`） |
| `route` | string | 被采样的路由路径 | 取自 `req.uri()`，与 Rocket 路由表对齐 | 决定该样本"应该有哪些 stage"，是校验 schema 的键。`/verify_all` 的 stage 集合与本文不同（见 §6.3） |
| `http_status` | u16 | HTTP 状态码 | `Response::status()` | **只有 2xx 参与 SLO**；`501`（设备缺失）会在极早返回，混进均值会把耗时拉低。错误样本可保留但必须打标 |
| `warm` | bool | 是否热路径 | 由采样器根据"本次之前是否已成功两次"设定 | 目前二值太粗：热/冷同时受 **AK 是否存在** 与 **page cache 是否热** 两个因子影响，二者量级差 10 倍 → 建议改枚举（见 §6.2） |
| `concurrency` | u16 | 客户端并发数 | 压测工具已知参数，直接透传 | 解释 `lock_wait_us` 的**唯一**依据。`concurrency=1` 时 `lock_wait_us≈0` 是预期，不是"锁没问题"的证据 |

### 3.2 端到端

| 字段 | 类型 | 含义 | 来源 | 判读要点 |
|------|------|------|------|----------|
| `e2e_server_us` | u64, µs | 服务端视角：`RequestLogger::on_request` 到 `on_response` 的墙钟 | `src/logging.rs:296` 起、`:305-307` 止（**已有实现**，现仅输出毫秒） | 这是唯一"官方"数字，是其他所有值的对账基准。它**不含** body 读入前的 TCP 收包、也不含响应写出后的内核发送 |
| `e2e_client_us` | u64, µs | 客户端视角：发起连接到读完 body | 压测/采集脚本（如 `curl -w '%{time_total}'`） | 与 `e2e_server_us` 的差值 = 网络 + 客户端解析 + 连接建立。示例：`131020 − 128400 = 2620 µs`（2.0%），其中含一次 TCP 连接；**若要研究服务端，差值应尽量压到 1% 以内（用 keep-alive 复用连接）** |

> `e2e_server_us` 与 `e2e_client_us` 一旦出现 `client < server`，说明两者不是同一时刻、同一请求，
> 数据不可用。

### 3.3 `stages` —— 12 个阶段

约定：**µs、整数、单调时钟、互斥**。按流程顺序排列（与代码执行顺序一致）。

| 字段 | 含义 | 源码位置 | 覆盖的工作 | 示例判读 |
|------|------|----------|------------|----------|
| `http_body_read_us` | 把请求体读成 `String` | `src/api.rs:382`（`body.map_err(..)` 那一行） | Rocket 的 `data="<body>"` 数据 guard 已把 body 读进内存，handler 只是**取结果** | ⚠️ **这个值在 handler 内根本测不到**，见 §4.3；示例 120 µs 实为框架开销，应归入残差 |
| `json_deserialize_us` | `serde_json::from_str::<QuoteTpmRequest>` | `src/api.rs:384` | 解析 `{"nonce":"..."}` 级别的极小 body | 40 µs 合理（~30 字节）。若 >500 µs 说明 body 变大或字段变多（`/verify_all` 会） |
| `nonce_validate_us` | `resolved_nonce` + `normalize_nonce` | `src/tpm.rs:374`、`src/tpm.rs:720` | 别名冲突检测、奇数长度检查、hex 解码、小写规范化 | 3 µs 合理（≤64 字节）。若 >100 µs 说明 hex 库被替换成慢实现 |
| `lock_wait_us` | 获取 `TpmInner` 互斥锁的等待时间 | `src/tpm.rs:702`（`TpmState::lock`） | **纯排队**，不含任何 TPM 工作 | 单并发 12 µs ≈ 无竞争。**并发下它可能占 80%**，必须与 TPM 工作量分开报（`T_queue` / `T_work` 两个数） |
| `scratch_new_us` | 建本次请求的临时目录 | `src/tpm.rs:1409`（`Scratch::new` → `fs::create_dir_all`） | `/tmp` 上一次 mkdir | 60 µs（tmpfs）。**若 `/tmp` 在机械盘或容器 overlay，会到毫秒级**，需记录 `/tmp` 所在设备 |
| `measure_and_extend_us` | 目录度量 + 整个 PCR 周期 | `src/tpm.rs:1055` | `measure_folder` + `tpm2_startup` + `pcrreset` + `pcrextend` + `pcrread` | ⚠️ **混合项**：把"文件系统 CPU/IO"和"4 次 TPM 子进程"混在一个数里，导致无法回答"TPM 占多少"。建议拆（见 §6.4）。示例 41200 与内部 units 矛盾，见 §5 |
| `ensure_ak_us` | 检查 AK 是否已持久化 | `src/tpm.rs:896`（`tpm2_getcap handles-persistent`） | 热路径 = 1 次子进程 + 文本匹配；冷路径 = 额外 7 次子进程建 AK | 18300 µs ≈ 一次 `tpm2-*` 冷启动成本（15–20 ms 是 CLI 主导，不是 TPM 运算）。**冷路径应在 `units` 里单独出 3 项**（`tpm2_createek/ak/evictcontrol_us`） |
| `create_quote_us` | 生成 TPM quote | `src/tpm.rs:979` | `flushcontext` + `tpm2_quote` + 3×`read_blob` + `normalize_nonce` | 最大的单项（示例占 48.6%）。**里面藏着 1 次 flushcontext 子进程**，已单独出现在 units 里 → 该 stage 的 units 之和必须能对齐，否则就是口径不一致（§5） |
| `tdx_report_us` | 生成 TDX 报告 | `src/tpm.rs:1240` → `src/attestation.rs:226` | `report_data_from` + `open_device` + `ioctl(TDX_CMD_GET_REPORT0)` | 示例 5310 中 5230 是 ioctl（98.5%）→ **TDX 报告成本就是一次 ioctl**，与 TPM 侧完全不在一个量级（5 ms vs 60 ms）。这是全文最有价值的结论，必须保留 |
| `ak_pubkey_us` | 取 AK 公钥 | `src/tpm.rs:953`（`ak_pubkey`） | 热路径 = 命中 `TpmInner.ak_pubkey` 缓存，仅一次 `String::clone`；冷路径 = `flushcontext` + `readpublic` + 读 PEM | **2 µs 是健康标志**（证明缓存生效）。若 >1 ms，说明缓存失效 → 每个请求都在刷 TPM，是典型性能回归信号。**必须作为告警项** |
| `scratch_drop_us` | 删除临时目录 | `src/tpm.rs:1435`（`Scratch` 的 `Drop`） | `fs::remove_dir_all` | 45 µs。注意它在**响应返回前**执行，所以计入 E2E；若与 scratch_new 一起 >1 ms，说明临时文件系统慢 |
| `serialize_us` | 响应序列化 | `src/api.rs:389`（`Json(...)` 构造点） | 组装 `AttestationAllResponse`（含 2874 字符的 `quote` 拼接串 + 2048 hex 字符的 report） | ⚠️ **真实序列化发生在 handler 返回之后**（`Json` 的 `Responder::respond_to`），handler 内测不到，见 §4.3；示例 380 µs 实际只能覆盖"struct 构造 + quote 字符串拼接" |

### 3.4 `units` —— 11 个时长 + 2 个计数

扁平字典，靠**名字前缀**表达归属。三类内容混在一起，读的时候必须先分类：

**(a) 文件系统度量簇**（父级：`measure_and_extend_us` 内的 `measure_folder_us`）

| 字段 | 含义 | 源码位置 | 判读要点 |
|------|------|----------|----------|
| `measure_folder_us` | 目录摘要总耗时 | `src/tpm.rs:520` | 示例 33800 = `2600 + 30900 + 300`（遍历 + 逐文件哈希 + 排序收尾），**这一项自洽**。注意它是 stage 级量却放在 `units` 里（§6.4） |
| `collect_regular_files_us` | 递归遍历 + 类型过滤 + 符号链接策略 | `src/tpm.rs:591` | 示例 2600 µs / 6 文件 ≈ 433 µs/文件 → 偏慢，典型"冷 inode"特征。**必须同时报文件数**，否则无法横向比较 |
| `read_and_hash_loop_us` | 逐文件 `fs::read` + `Sha256::digest` 循环 | `src/tpm.rs:562`–`580` | 示例 30900 µs / 48213 B ≈ **1.56 MB/s** → 明显是冷 page cache（热缓存同规模应 <1 ms）。这是全表最需要标注条件的一项 |

**(b) TPM CLI 簇**（一次子进程一项，父级：分散在多个 stage 里）

| 字段 | 对应命令 | 源码位置 | 判读要点 |
|------|----------|----------|----------|
| `tpm2_startup_us` | `tpm2_startup -c` | `src/tpm.rs:827` | 每次请求都跑；已启动时靠"失败即成功"走快路径，但**仍要付一次 `fork/exec`** |
| `tpm2_pcrreset_us` | `tpm2_pcrreset <pcr>` | `src/tpm.rs:851` | 不可重置 PCR 会返回 500，耗时会异常短 → 错误样本要单独剔除 |
| `tpm2_pcrextend_us` | `tpm2_pcrextend <pcr>:<alg>=<digest>` | `src/tpm.rs:868` | 与 `reset` 量级接近是正常的（都是"建连 + 一条命令"） |
| `tpm2_pcrread_us` | `tpm2_pcrread <alg>:<pcr> -o pcr.bin` | `src/tpm.rs:873` | **含一次落盘**（子进程写 `pcr.bin`）+ 一次 `fs::read`（`src/tpm.rs:875`），比同类命令略高是正常的 |
| `tpm2_getcap_us` | `tpm2_getcap handles-persistent` | `src/tpm.rs:897` | 属于 `ensure_ak_us` 的内部；即使 AK 已存在也要查，是固定开销 |
| `tpm2_flushcontext_us` | `tpm2_flushcontext -t` | `src/tpm.rs:844` | **每次 quote 前都 flush**（`src/tpm.rs:984`），且冷路径会连刷多次；模拟器槽位少，**不能省**，但要计入成本 |
| `tpm2_quote_us` | `tpm2_quote -q <nonce> ...` | `src/tpm.rs:990` | 唯一含 **TPM 内部 RSA-SSA 签名** 的项（真实运算约 10–30 ms）；其余 `tpm2_*` 的数字基本等于"CLI 冷启动 + TCTI 建连" |
| `ioctl_get_report_us` | `ioctl(TDX_CMD_GET_REPORT0)` | `src/attestation.rs:165`，调用点 `:235` | 子项属于 `tdx_report_us`；**只覆盖 ioctl 本身**，不含 `open("/dev/tdx_guest")`（5.3 ms 中约 80 µs 是 open/填充，示例可接受） |

**(c) 计数**（不是时长，禁止求和进耗时）

| 字段 | 含义 | 来源 | 用法 |
|------|------|------|------|
| `files_measured` | 本次度量的普通文件数 | `measurement.measurement.len()`，`src/tpm.rs:1068` 附近 | 与 `read_and_hash_loop_us` 做**归一化**（µs/文件），才能跨目录比较 |
| `bytes_measured` | 本次度量的总字节数 | 各 `MeasuredFile.size` 求和 | 算**吞吐**（B/µs），是判断"冷缓存还是热缓存"的关键判据 |

> 缺一个计数：`tpm2_command_count`（本次起了几个子进程）。热路径应为 **7**，冷路径 16。
> 有了它，`Σ(tpm2_*)/count` 就能直接给出"单次 CLI 平均成本"，是最能说明问题的派生指标。

### 3.5 派生与校验

| 字段 | 类型 | 计算方式 | 应有性质 |
|------|------|----------|----------|
| `unattributed_us` | i64, µs | `e2e_server_us − Σ(stages 中所有互斥项)` | 应为一个**小数（可为负几百 µs）**：负值来自"stage 计时点互相重叠"（例如 stage 计时器包含了下级计时器自身的开销）或采样边界。**绝对值应 < e2e_server 的 10%** |
| `checksum_ok` | bool | 由采集工具计算，不手填：①`abs(unattributed_us) ≤ max(1000, 5%·e2e_server)`；②每个 stage ≥ 其下 units 之和的 99%；③`Σ(tpm2_*) ≤ e2e_server` | 为 `false` 的样本**必须整条丢弃**，不能"看起来差不多就留下"。示例这条按规则①算应为 `false`（见 §5） |

---

## 4. 每个字段怎么度量

### 4.1 通用规则（先定规矩，再写代码）

1. **时钟**：只用 `std::time::Instant`（单调），禁止 `SystemTime`；`e2e_client_us` 例外，它跨进程。
2. **单位**：内部一律 `u64` 微秒；禁止先存毫秒再乘 1000（会丢精度，`as_millis()` 会把 60 µs 变成 0）。
3. **零开销失败**：用 RAII guard 在 `Drop` 里落账，保证 `?` 提前返回时**错误路径也有耗时样本**。
4. **不用全局锁存样本**：样本放进请求上下文（Rocket `local_cache` / 线程局部），否则埋点本身会变成
   热点，污染 `lock_wait_us`。
5. **一次请求一行**：绝不为每条样本写一行日志 —— 日志每行都 `flush()`（`src/logging.rs:108`），
   写日志会污染被测对象。
6. **埋点顺序固定**：`t0 = Instant::now()` 必须在 stage 的**入口第一行**，`elapsed` 在**出口**取；
   跨越 `?` 的必须用 guard。
7. **先跑通再优化**：`MODE=off` 时所有埋点必须是零成本的 `#[cfg]` 空实现，否则"测了和不测"的
   对比就不成立。

### 4.2 逐字段度量方法

| 字段 | 计时起点 | 计时终点 | 埋点位置 | 常见错误 |
|------|----------|----------|----------|----------|
| `e2e_server_us` | `on_request` 第一行 | `on_response` 第一行 | `src/logging.rs:296` / `:305`（已有，改成 µs 输出即可） | 用 `SystemTime`；把 `on_response` 放在日志写盘之后 |
| `e2e_client_us` | 客户端发出首字节前 | 读完 body 最后一个字节 | 采集脚本 `curl -w` / `reqwest` 包裹 | 未复用连接（每次算上 TCP+握手）；未扣除脚本自身 JSON 解析 |
| `http_body_read_us` | — | — | **测不到**，见 §4.3 | 在 handler 内给 `body.map_err(...)` 那行打点 → 测到的只是 `Result` 的 move（≈0），却报出 120 µs |
| `json_deserialize_us` | `from_str` 调用前 | 返回 `Ok/Err` 时（**含错误分支**） | `src/api.rs:384` | 只测成功路径；把 `hex::decode` 也算进来（那是 `nonce_validate`） |
| `nonce_validate_us` | `resolved_nonce` 入口 | 返回 `(String, usize)` 时 | `src/tpm.rs:374`（内部还可细分 `normalize_nonce` `:720`） | 把 `to_ascii_lowercase` 的分配成本漏掉 |
| `lock_wait_us` | 调用 `state.lock()` 之前 | `lock()` 返回 guard 之后 | `src/tpm.rs:702`，调用点 `src/tpm.rs:1219` | **在拿到 guard 之后才开始计时** → 等锁时间恒为 0，把并发问题藏起来 |
| `scratch_new_us` | `Scratch::new` 入口 | 返回 `Ok(Self)` 时 | `src/tpm.rs:1409` | 忘了记录 `/tmp` 所在文件系统；容器 overlay 下结论完全不同 |
| `measure_and_extend_us` | 函数入口 | 返回 `(measurement, pcr_value)` 时 | `src/tpm.rs:1055` | 把它当成"TPM 耗时" —— 它 82% 是文件度量（示例 33800/41200） |
| `ensure_ak_us` | 函数入口 | 返回 `Ok(())` 时 | `src/tpm.rs:896` | 冷/热混采；未记录本次是否走了 `createek` 分支 |
| `create_quote_us` | 函数入口 | 返回 `(TpmEvidence, usize)` 时 | `src/tpm.rs:979` | 把 `read_blob` 的 `base64(hex())` 双层编码算进 TPM 时间 |
| `tdx_report_us` | 函数入口 | 返回 `Vec<u8>` 时 | `src/tpm.rs:1240` 或 `src/attestation.rs:226` | 把 `hex::encode(report)`（`src/tpm.rs:1247`）算进去 → 2048 字符编码会被混入 TDX 成本 |
| `ak_pubkey_us` | 函数入口 | 返回 PEM 时 | `src/tpm.rs:953` | 不区分"缓存命中/未命中"，导致这一项时大时小无法解释 |
| `scratch_drop_us` | `Drop::drop` 入口 | `drop` 返回前 | `src/tpm.rs:1435` | 忘记它是 `Drop` → 在函数末尾手写计时会漏掉 |
| `serialize_us` | — | — | **测不到真值**，见 §4.3 | 在 `Json(...)` 构造处计时 → 测到的是 struct 构造，不是序列化 |
| `measure_folder_us` | 函数入口 | 返回 `FolderMeasurement` 时 | `src/tpm.rs:520` | 不含 `as_tpm_measurement` 的 clone（那是另一个点） |
| `collect_regular_files_us` | 函数入口 | 递归返回时 | `src/tpm.rs:591` | 只测顶层、不测递归 → 子目录开销丢失 |
| `read_and_hash_loop_us` | 循环前 | 循环结束 | `src/tpm.rs:562`–`580` | **在循环内每文件打两次点**：文件很小时，计时本身（~50 ns×2）会扭曲结果 → 用局部 `u128` 纳秒累加，循环结束再落账 |
| `tpm2_*_us` | `Command::new(...)` 之前 | `output()` 返回、`status` 判定后 | `src/tpm.rs:757`（`tpm2()` 内按 `subcommand` 分支记录） | 用 `spawn()`+`wait()` 分开计时却只累加 `wait()`，漏掉 `fork/exec` 与 TCTI 建连（那才是大头） |
| `ioctl_get_report_us` | `ioctl(...)` 调用前 | 返回后 | `src/attestation.rs:235` | 把 `open_device`（`:228`）算进去；把 `report_data_from`（`:227`）算进去 |
| `files_measured` | — | — | `measurement.measurement.len()` | 用手写的计数器（会与 `collect_regular_files` 的过滤规则不一致） |
| `bytes_measured` | — | — | 各 `MeasuredFile.size` 求和 | 用目录总大小（含被跳过的非普通文件） |
| `unattributed_us` | — | — | 采集器计算，不入业务代码 | 手工填写；把残差摊给某个 stage 让表"看起来对" |
| `checksum_ok` | — | — | 采集器计算 | 恒填 `true`；不做父子包含检查 |

### 4.3 三个"在 handler 内测不到"的字段（必须特殊处理）

这三个字段是这份 schema 最大的坑，直接决定了残差能不能解释干净：

**① `http_body_read_us` —— 数据 guard 在 handler 之前执行**

Rocket 的 `data = "<body>"` 会在**调用 handler 之前**完成 `FromData`（读取 + UTF-8 校验），
handler 收到的只是 `Result<String, io::Error>`。所以 `src/api.rs:382` 那行打点只能测到"取走结果"。

三种正确做法（任选其一，**不要**假装测到了）：

| 方案 | 做法 | 代价 |
|------|------|------|
| A（推荐） | 承认它属于框架开销，并入 `unattributed_us`，schema 里删掉这个字段 | 无 |
| B | 在 `on_request` 打点，在 handler 第一行再打点，差值即"路由 + 数据 guard"合计 | 与路由开销不可分 |
| C | 自定义 `FromData` guard，在 `from_data` 内计时 | 要改路由签名 |

**② `serialize_us` —— `Json<T>` 的序列化发生在 handler 返回之后**

`Json<AttestationAllResponse>` 的 `Responder::respond_to` 才真正调用 `serde_json::to_vec`，
而它在 handler 返回后才执行。所以 `src/api.rs:389` 打点测到的是"struct 构造 + `quote` 字符串拼接"。

| 方案 | 做法 |
|------|------|
| A（推荐） | 改名 `build_response_us`（诚实反映内容），真正序列化并入残差 |
| B | handler 内先 `serde_json::to_string(&resp)` 再返回 `(Status, String)`，就能精确测到 |

**③ `scratch_new_us` / `scratch_drop_us` 之间的"框架残差"**

`e2e_server` 还包含：Rocket 路由匹配、body 限流检查（`limits.string = 2 MiB`，见 `src/lib.rs:87`）、
`logging` 两行落盘、以及 TCP 写回。这些没有对应字段，只能落在 `unattributed_us` 里。
**判断标准**：若 `unattributed_us` 稳定在 300–2000 µs，属正常；若 >5 ms，说明漏了一个大项。

### 4.4 采集矩阵（不控制变量，字段注释再准也没用）

| 维度 | 取值 | 目的 |
|------|------|------|
| 冷/热 | 冷 AK（先 `tpm2_evictcontrol` 清掉） / 热 AK | `ensure_ak_us`、`ak_pubkey_us` 差 100 倍 |
| page cache | 冷（`echo 3 > /proc/sys/vm/drop_caches`） / 热 | `read_and_hash_loop_us` 差 10–30 倍 |
| 并发 | 1 / 2 / 4 / 8 | 只有 >1 才能让 `lock_wait_us` 有值 |
| 目录规模 | 6 文件/48 KB → 100 文件 → 1000 文件 | `measure_folder` 的线性项 |
| 样本量 | 每组 ≥30（建议 100），含 3 次 warmup 丢弃 | 尾部延迟 |

**报告规范**：每个字段报 `p50 / p90 / p99 / max`，并注明上述四个条件。只报均值等于放弃解释力。

---

## 5. 数值自洽性核对（为什么示例数字不能当基线）

用这份样本自身的字段互相验算，有三处对不上。这不是挑错，而是**说明"自洽性校验"为什么必须是工具自动做的**：

| # | 校验项 | 应有的关系 | 示例实际 | 结论 |
|---|--------|------------|----------|------|
| 1 | 阶段可加性 | `Σ stages ≈ e2e_server` | `Σ = 127872` vs `e2e_server = 128400` → 应为 **+528** | 声明的 `unattributed_us = −1288` 与自身字段矛盾；`checksum_ok` 应为 `false` |
| 2 | 父子包含（度量簇） | `measure_folder_us ≈ collect + read_hash + 收尾` | `2600 + 30900 = 33500`，与 `33800` 差 300 | ✅ 这一簇**自洽**，说明作者确实测过 `measure_folder` |
| 3 | 父子包含（PCR 簇） | `measure_and_extend_us ≥ Σ(PCR 相关 units)` | `41200` vs `18100+17800+18200+19500 = 73600` | ❌ 子项是父项的 **1.8 倍**，物理上不可能 |
| 4 | 全局上限 | `Σ(tpm2_*) ≤ e2e_server` | `134600` vs `128400` | ❌ 仅 TPM CLI 一项就超过整条请求耗时 |
| 5 | 量级一致性 | `create_quote_us ≈ flushcontext + quote + 读 blob` | `17500 + 25600 = 43100` vs `62400` | ❌ 差 19300 µs，而读 3 个小文件不可能要 19 ms |

**诊断结论**：`stages` 与 `units` 出自**两个不同的计时口径** ——
`stages` 里的 `measure_and_extend_us`（41200）隐含"4 次 PCR 子进程共 7400 µs，平均 1.85 ms/次"，
而 `units` 里的 `tpm2_*` 平均 18.4 ms/次。两者差 **10 倍**，最可能的解释是：`units` 的
`tpm2_*` 数字来自**独立基准脚本**（例如单独跑 `tpm2_getcap` 计时），而不是在同一次请求内测得。

**这直接决定后续工作的第一步**：要么所有 `tpm2_*` 都从同一次请求的 `tpm::tpm2`
（`src/tpm.rs:757`）内部采集（推荐，口径统一），要么在 schema 里加 `source: "request" | "benchmark"`
字段明确标注来源。**绝不能让两种来源的数字出现在同一张表里求和。**

> 另外两个"量级可疑、需要现场核实"的数字（不算矛盾，但要标注条件）：
> * `read_and_hash_loop_us`：48213 B / 30900 µs ≈ **1.56 MB/s** → 典型冷 page cache；
> * `ensure_ak_us`：18.3 ms 几乎全是 `fork/exec` + mssim 建连，**不是** TPM 运算。

---

## 6. schema 修订建议（v2）

### 6.1 补环境上下文（否则数字不可复现）

```json
"env": {
  "measure_dir": "/root/tdx-attestation-server/workspace/src",
  "pcr_index": 16,
  "hash_algorithm": "sha256",
  "tpm_mode": "mssim",              // mssim | hardware
  "tcti": "mssim:host=127.0.0.1,port=2321",
  "ak_handle": "0x81010002",
  "tmp_fs": "tmpfs",                // /tmp 所在文件系统
  "log_dev": "tmpfs",               // 日志目录所在文件系统
  "cpu": 8, "kernel": "6.x", "commit": "abc1234"
}
```

没有 `env`，`read_and_hash_loop_us = 30900` 到底是"代码慢"还是"盘冷"永远说不清。

### 6.2 把 `warm` 拆成两个因子

```json
"ak_state": "persisted",        // persisted | created_this_run
"cache_state": "cold",          // cold | warm  （page cache）
"iter": 17,                      // 本次运行的序号（warmup 用 iter<3 剔除）
"sample_id": "20261106T070451Z-000017"
```

### 6.3 让 `stages` 严格互斥，把混合项拆开

```json
"stages": {
  "measure_folder_us": 33800,      // ← 从 units 提升上来
  "pcr_cycle_us": 7400,            // ← 新增：startup+reset+extend+read
  "ensure_ak_us": 18300,
  "quote_us": 62400,
  "tdx_report_us": 5310,
  ...
}
```

这样 `Σ stages` 才真的等于 `e2e_server`，且能一眼回答"TPM vs 文件系统 vs TDX 各占多少"。
（当前版本做不到，因为 `measure_and_extend_us` 把两类工作焊在一起。）

### 6.4 给 `units` 加 `parent`，或改用点号键

```json
"units": {
  "measure_folder.collect_us": 2600,
  "measure_folder.read_hash_us": 30900,
  "pcr_cycle.startup_us": 18100,
  "quote.flush_us": 17500,
  "quote.quote_us": 25600,
  "tdx.ioctl_us": 5230
}
```

扁平 + 前缀已经不够用（`measure_folder_us` 到底属于谁，读者要猜）。

### 6.5 计数单独一组

```json
"counters": {
  "files_measured": 6,
  "bytes_measured": 48213,
  "tpm2_execs": 7,                 // ← 强烈建议新增
  "scratch_files_written": 3
}
```

`tpm2_execs` 配合 `Σ(tpm2_*)` 可直接推出"单次 CLI 平均成本"，是最有解释力的派生指标。

### 6.6 验证侧需要**另一套** stage（不能复用生成侧）

`/verify_all` 没有 TPM 连接、没有目录度量，字段完全不同：

```json
"route": "/verify_all",
"stages": {
  "http_body_read_us": 0,
  "json_deserialize_us": 900,      // 4 KB body，是生成侧的 20 倍
  "tdx_verify_us": 5400,
  "decode_blob_us": 60,
  "fs_write_us": 120,
  "tpm_checkquote_us": 21000,
  "build_response_us": 3
}
```

强行套用生成侧 schema 会逼着采集者填 0 或编造，污染数据。

---

## 7. 后续工作清单

按依赖顺序排列（**均不含业务逻辑改动**）：

| # | 任务 | 产出 | 判定标准 |
|---|------|------|----------|
| 1 | 定 schema v2（按 §6 修订），写 JSON Schema 文件 | `schema/sample.schema.json` | 能校验本文样本；对 §5 的矛盾样本返回 `false` |
| 2 | 实现 `Sample` 结构 + RAII guard（`Instant`/µs/Drop 落账） | 一个 `measure` 模块 | `MODE=off` 编译后零成本 |
| 3 | 在 12 个 stage 点埋点（§4.2 的表） | 生成侧样本能填满 `stages` | `Σ stages` 与 `e2e_server` 残差 <5% |
| 4 | 修改 `tpm::tpm2`（`src/tpm.rs:757`）按 subcommand 记录 ×7 | `units.tpm2_*` 齐全 | `tpm2_execs == 7`（热）/`16`（冷） |
| 5 | 处理 §4.3 的三个"测不到"字段：删或改名，不伪造 | schema 与实现一致 | 不再出现 handler 内的 body/serialize 计时 |
| 6 | 写采集器：NDJSON 输出 + 自动算 `unattributed_us`/`checksum_ok` | `tools/collect.sh` 或 Rust bin | 不自洽样本自动丢弃并计数 |
| 7 | 按 §4.4 矩阵跑批（冷/热 × cache × 并发 × 规模） | 原始 NDJSON 数据集 | 每组 ≥100 样本 |
| 8 | 汇总脚本：p50/p90/p99 + 占比表；生成侧与验证侧分开 | 报告表格 | 占比之和 ≈100% |
| 9 | 复核结论：TPM CLI 占比、TDX 5 ms 是否为真、`measure_folder` 是否随规模线性 | 一页结论 | 与 §5 的诊断一致或推翻它 |

**最该先做的是 #1 和 #6**：没有自动校验，后面所有采集都可能重蹈本文档示例的覆辙（stage 与 unit 出自两个口径）。

---

## 8. 与主方案文档的 M 编号映射

| 样本字段 | 主文档编号 | 备注 |
|----------|------------|------|
| `e2e_client_us` | M01 | |
| `e2e_server_us` | M02 | 已有实现，仅需改 µs |
| `json_deserialize_us` | M11 | |
| `nonce_validate_us` | M12 + M13 | 合并为一个 stage |
| `lock_wait_us` | M14 | 并发下的关键 |
| `scratch_new_us` / `scratch_drop_us` | M15 / M16 | |
| `measure_and_extend_us` | M20 | 建议拆为 M20a/M20b（§6.3） |
| `measure_folder_us` | M21 | |
| `collect_regular_files_us` | M23 | |
| `read_and_hash_loop_us` | M25 | 必须带 `bytes_measured` |
| `ensure_ak_us` | M35 | |
| `create_quote_us` | M36（子项 M37/M38/M39） | |
| `tdx_report_us` | M40（子项 M43） | |
| `ak_pubkey_us` | M3A | 缓存健康指标 |
| `tpm2_*_us` | M30 + M31–M38 | 统一从 `tpm::tpm2` 采集 |
| `ioctl_get_report_us` | M43 | |
| `files_measured` / `bytes_measured` | 新增计数器 | 主文档未要求，但对解释 `read_and_hash_loop_us` 必需 |
| `unattributed_us` / `checksum_ok` | §5 覆盖率核对 | 主文档的"残差单列"原则 |

---

## 9. 实现落地（已合入代码）

本节记录实现与本文档的对应关系，以及那些"理论字段"在代码里到底是怎么落的。

### 9.1 怎么开关

| 构建 | 行为 |
|------|------|
| `cargo run` / `cargo build` / `cargo test`（`debug_assertions` 开） | **每个请求**写一份 JSON 到 `log/json/` |
| `cargo build --release`（`debug_assertions` 关） | 不编译任何计时/写文件代码；仅剩一个零大小 guard，无 `Instant::now()`、无分配、无 I/O |

目录可用 `TDX_TIMING_DIR` 覆盖（与 `TDX_LOG_DIR` 同一风格），默认 `<项目根>/log/json`。
文件名 `YYYYMMDDTHHMMSSZ-<pid>-<seq>.json`，一条请求一个文件，进程内序号保证同秒内不冲突。

### 9.2 代码位置

| 部分 | 位置 |
|------|------|
| 录制器 / 渲染 / 校验 | `src/metrics.rs` |
| 请求边界（到达、状态码、e2e） | `src/logging.rs` 的 `RequestLogger` fairing（`on_request` / `on_response`） |
| 每个 handler 的入口与阶段 | `src/api.rs`（`_timing: Timing` 参数 + `enter_handler()`） |
| 后端阶段与单元 | `src/tpm.rs`、`src/attestation.rs`（`span` / `unit` / `count` / `mark_cold`） |

### 9.3 字段实现口径（与 §4.3 的约定一致）

| 字段 | 实现口径 |
|------|----------|
| `e2e_server_us` | fairing：`on_request` 到 `on_response`，与审计日志里的 `latency_ms` 同源，只是精度为 µs |
| `http_body_read_us` | handler 第一行相对**请求到达**的差值 = 路由匹配 + 数据 guard。它是"最接近的诚实值"，不是纯 body 读取（见 §4.3 ①） |
| `serialize_us` | debug 下把响应体**再序列化一次**并计时（真实序列化发生在 handler 返回之后），因此是上界而非旁路值（见 §4.3 ②） |
| `e2e_client_us` | **恒为 `null`**：服务端无法观测客户端往返，填 0 会违反 §3.2 的 `client ≥ server` 不变式 |
| `warm` | 本次请求没有建 AK（`ensure_ak` 未进入创建分支）且 AK 公钥**缓存命中** 时为 `true` |
| `concurrency` | 服务端在途请求数（到达时刻），不是压测工具配置的并发度；单请求压测时两者一致 |
| `unattributed_us` | `e2e_server_us − Σ(stages)`，由代码计算，绝不手工填写 |
| `checksum_ok` | ①残差 ≤ `max(1000, 5%·e2e)`；②`measure_folder_us ≥ collect + read_hash`；③`tdx_report_us ≥ ioctl_get_report_us`；④`Σ(tpm2_*) ≤ e2e`。任一不满足即 `false` |

### 9.4 与本文档的已知差异（以代码为准）

1. `files_measured` / `bytes_measured` 仍放在 `units` 内（按本文档 §1 的形状），但**不参与任何求和**；
   §6.5 建议的独立 `counters` 组尚未采用。
2. 计数器与时长共用一个 `units` 对象，读数据时必须按"有无 `_us` 后缀"区分（校验器已如此处理）。
3. `/verify-report`、`/parse-report`、`/quote_tpm`、`/information_tpm`、`/verify_all` 各有自己的
   stage 子集（如 `report_decode_us`、`tdx_verify_us`、`tpm_verify_us`），不套用 `/attestation_all` 的 12 项；
   这符合 §6.6"验证侧不能复用生成侧 schema"的结论。
4. 未实现 §6 的 `env` 上下文块与 `sample_id`/`iter`；文件名列已承担 `sample_id` 的部分职责。
5. `thread_local` 记录器的作用域是**一次 handler 调用**（同步调用树，无 `.await`），
   请求级数据本身存在 `Request::local_cache`，跨线程迁移不受影响。
