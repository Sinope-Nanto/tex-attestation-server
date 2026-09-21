# TPM 2.0 模拟器

本目录是 **Microsoft / TCG TPM 2.0 参考实现模拟器**（`tpm2-simulator`）的
独立部署结果，可以直接启动、停止、测试和使用。

## 概述

本目录包含由微软维护的官方 TCG 参考实现中附带的 TPM 2.0 模拟器的可运行
构建产物。该模拟器模拟一个 TPM 2.0 设备，并通过自定义的 TCP 协议对外
提供服务，因此 TSS 协议栈（例如 `tpm2-tss` / `tpm2-tools`）以及其他客户端
可以像访问真实 TPM 一样访问它。

模拟器会启动两个 TCP 服务：

| 服务            | 默认端口 | 用途                                          |
|-----------------|----------|-----------------------------------------------|
| TPM 命令端口    | `2321`   | TPM 2.0 命令 / 响应数据流                     |
| 平台端口        | `2322`   | 平台信号（上电/断电、复位、NV、物理存在等）   |

平台端口始终等于「命令端口 + 1」。

## 源码来源

`bin/` 中的二进制文件由本地源码目录构建而来：

```
../../ms-tpm-20-ref
```

源码版本（git）：

```
commit ee21db0a941decd3cac67925ea3310873af60ab3
Date:   2024-10-04 11:12:27 -0700
```

## 构建环境

| 项目        | 值                                                          |
|-------------|-------------------------------------------------------------|
| 操作系统    | Ubuntu 24.04.4 LTS (Noble Numbat)                           |
| 内核        | Linux 6.8.0-137-generic, x86_64                             |
| 编译器      | gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0                 |
| Make        | GNU Make 4.3                                                |
| OpenSSL     | OpenSSL 3.0.13 30 Jan 2024（库 `libcrypto.so.3`）           |
| Autotools   | autoconf、automake、autoreconf、libtool                     |
| 其他        | pkg-config 1.8.1、autoconf-archive、libssl-dev              |

## 目录结构

```
tpm-simu/
├── bin/
│   └── tpm2-simulator        # 编译好的模拟器二进制文件
├── scripts/
│   ├── start.sh              # 后台启动模拟器
│   ├── stop.sh               # 停止模拟器
│   ├── status.sh             # 输出 RUNNING / STOPPED
│   └── test.sh               # 端到端冒烟测试
├── state/                    # 运行时状态（NVChip、端口文件）
│   ├── NVChip                # 持久化的 NV 存储镜像
│   ├── command.port          # 模拟器实际绑定的命令端口
│   └── platform.port         # 模拟器实际绑定的平台端口
├── logs/
│   └── tpm-simulator.log     # 模拟器的 stdout/stderr
├── tpm-simulator.pid         # 运行中模拟器的 PID（启动时创建）
├── README.md                 # 英文文档
└── README.zh.md              # 本文件
```

## 构建过程

以下命令是实际执行过的、用于生成 `bin/tpm2-simulator` 的步骤：

```bash
# 1. 安装构建依赖（只安装缺失的部分）
apt-get update
apt-get install -y autoconf automake autoconf-archive libtool libssl-dev

# 2. 生成 autotools 构建系统
cd ms-tpm-20-ref/TPMCmd
./bootstrap

# 3. 配置
./configure

# 4. 编译
make -j$(nproc)
```

生成的二进制文件位于：

```
ms-tpm-20-ref/TPMCmd/Simulator/src/tpm2-simulator
```

随后被复制到本部署目录的 `bin/tpm2-simulator`。

## 启动

```bash
./scripts/start.sh
```

该脚本会在后台启动模拟器，把 PID 写入 `tpm-simulator.pid`，并把所有运行时
状态保存到 `state/` 目录。

支持的环境变量：

| 变量            | 默认值   | 含义                                              |
|-----------------|----------|---------------------------------------------------|
| `TPM_SIM_PORT`  | `2321`   | 基础 TCP 端口（平台端口为 `+1`）                  |
| `TPM_SIM_ARGS`  | （空）   | 额外参数，例如 `-m` 表示强制重新制造              |

使用自定义端口启动：

```bash
TPM_SIM_PORT=3000 ./scripts/start.sh
```

## 停止

```bash
./scripts/stop.sh
```

脚本会发送 `SIGTERM`，等待进程退出，并删除 PID 文件。如果进程在 10 秒内
没有退出，会使用 `SIGKILL` 强制结束。

## 状态

```bash
./scripts/status.sh
```

输出 `RUNNING` 或 `STOPPED`。当模拟器运行时，还会输出 PID 以及实际监听的
端口。

## 测试

```bash
./scripts/test.sh
```

执行完整的冒烟测试：

1. 二进制文件存在且可执行
2. `start.sh` 能成功启动模拟器
3. TCP 命令端口确实处于监听状态
4. 真实的 TPM 命令往返（通过 `tpm2-tools` 的 `tpm2_getrandom` /
   `tpm2_getcap`，或直接使用模拟器协议发送 `TPM2_GetCapability`）
5. 重启（`stop` + `start` + `status`）正常
6. 测试结束时模拟器保持 `RUNNING` 状态

## 网络接口

模拟器绑定到 **所有网络接口**（`0.0.0.0`）上的配置端口。当前实现没有提供
限制绑定地址的选项。

| 协议 | 地址      | 端口（默认） | 用途            |
|------|-----------|--------------|-----------------|
| TCP  | 0.0.0.0   | 2321         | TPM 命令端口    |
| TCP  | 0.0.0.0   | 2322         | 平台端口        |

## TPM 客户端使用

本部署已使用 Ubuntu 仓库中的 `tpm2-tools` 以及 `mssim` TCTI 进行过验证：

```bash
export TPM2TOOLS_TCTI="mssim:host=127.0.0.1,port=2321"

# 上电 / 启动（模拟器启动后需要执行一次）
tpm2_startup -c

# 无破坏性冒烟测试
tpm2_getrandom 8
tpm2_getcap properties-fixed
```

上述命令均已在本部署上成功执行，并返回了有效的 TPM 响应。

如果没有安装 `tpm2-tools`，任何支持微软模拟器协议（`mssim`）的 TSS 协议栈
都可以连接到 `127.0.0.1:2321`。模拟器使用标准的微软模拟器 TCP 协议，
协议定义见 `TPMCmd/Simulator/include/TpmTcpProtocol.h`。

## 状态存储

所有持久化状态都保存在 `state/` 目录：

- `NVChip` —— TPM 的 NV 存储镜像。首次启动时创建，之后随 TPM 写入 NV 数据
  而更新。删除该文件会强制 TPM 在下次启动时重新制造。
- `command.port` / `platform.port` —— 模拟器实际绑定的端口。当使用
  `--pick_ports` 且请求端口已被占用时，这两个文件尤其有用。

模拟器启动时的工作目录被设置为 `state/`，因此这些文件都会写入该目录，
而不会污染部署根目录。

## 日志

模拟器的 stdout/stderr 会追加写入：

```
logs/tpm-simulator.log
```

## 故障排查

### 端口已被占用

如果 `start.sh` 报告端口已被占用，可以停止占用该端口的进程，或者换一个
端口启动：

```bash
TPM_SIM_PORT=3000 ./scripts/start.sh
```

也可以通过 `TPM_SIM_ARGS` 传入 `-p`（pick ports），让模拟器自动选择下一个
空闲端口。此时请从 `state/command.port` 读取实际端口。

### OpenSSL 构建问题

构建需要 `libssl-dev` 以及受支持的 OpenSSL 版本。在 Ubuntu 上：

```bash
apt-get install -y libssl-dev
```

如果出现关于 OpenSSL 3.0 已弃用 API 的错误，请注意构建已经传入了
`-Wno-error=deprecated-declarations`，不要移除它。

### PID 文件过期

如果 `tpm-simulator.pid` 存在但进程已经不存在，`stop.sh` 和 `start.sh`
会自动检测并删除该过期文件。也可以手动删除：

```bash
rm -f tpm-simulator.pid
```

### 缺少构建依赖

如果 `./bootstrap` 失败，请安装 autotools 相关软件包：

```bash
apt-get install -y autoconf automake autoconf-archive libtool pkg-config
```

## 安全声明

这是一个 **软件 TPM 模拟器**，仅适用于：

- 开发
- 测试
- 教学
- 协议实验

它 **不提供** 物理 TPM 的硬件安全属性。模拟器处理的密钥和机密不受任何
硬件信任根的保护，绝不能用于保护真实的生产机密。
