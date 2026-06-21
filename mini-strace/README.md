# mini-strace

> 基于 ptrace 的 x86_64 Linux syscall 跟踪器 —— 从 syscall 事件流、参数解码、fd/VMA/socket 状态关联到 seccomp-BPF 过滤、错误注入与证据级诊断。

## 目录

- [它能解决什么](#它能解决什么)
- [核心机制](#核心机制)
- [快速开始](#快速开始)
- [命令速查](#命令速查)
- [代码架构](#代码架构)
- [技术栈](#技术栈)
- [Demos](#demos)
- [使用场景与实战](#使用场景与实战)
- [边界与权限](#边界与权限)
- [许可说明](#许可说明)

---

## 它能解决什么

| 场景 | 典型信号 | 本工具能回答 |
| --- | --- | --- |
| 程序启动慢 | 启动阶段卡顿 | 是否大量 `openat/stat/access` 在查找配置、动态库、字体 |
| 文件路径错误 | `ENOENT / EACCES` | 具体哪个路径打开失败、errno 是什么 |
| 输出异常 | 没输出或输出不全 | 是否调用 `write(1/2,...)`、返回值是否短写或失败 |
| 网络卡住 | 请求迟迟不返回 | 是否卡在 `connect/recvfrom/epoll_wait/futex`，连到哪个 peer |
| 内存映射异常 | VIRT/RSS 异常 | 是否频繁 `mmap/munmap/mprotect/brk` |
| syscall 失败率高 | 程序没显式报错 | 哪些 syscall 返回负 errno、失败多少次 |
| 被 sandbox 拦截 | 莫名 `EPERM` / 被 kill | 是不是 seccomp 过滤器拦的、被哪条规则拦的 |
| 错误处理没覆盖 | 想测异常路径 | 用 `--inject` 给指定 syscall 注入错误，触发重试/降级逻辑 |

只想临时看一次「它调了什么 syscall」，`strace` 更成熟更快。本工具的价值在**亲手实现的 ptrace 事件源、稳定的 JSON 事件流、fd/VMA/socket 状态关联、以及 seccomp 过滤 / 错误注入 / 拒因归因这些内核协作面**。

### 一次调用能观测到什么

针对启动的命令或 attach 的进程，按所选模式给出：

| 维度 | 具体内容 | 数据来源 | 触发参数 |
| --- | --- | --- | --- |
| **syscall 事件流** | 每次 syscall 的 entry/exit 配对、参数解码、返回值、errno、耗时 | `ptrace(PTRACE_SYSCALL)` + `PTRACE_GET_SYSCALL_INFO` | 默认 |
| **JSON 事件流** | 一行一个完整 syscall（机器可读，字段稳定） | 同上 | `--json` |
| **参数解码** | 路径/flags/sockaddr/iovec/clone flags/errno 名称与转义字符串 | `process_vm_readv` 读 tracee 内存 | 默认（`--raw` 关闭） |
| **fd/VMA/socket 关联** | `read(3</etc/ld.so.cache>)`、`recvfrom(7<TCP 10.0.0.5:443>)`、mmap 区间 | 增量状态模型（标 `known`/`inferred`） | `--state` |
| **统计汇总** | 按 syscall 的 count/errors/total/avg/max，默认按总耗时排序 | 事件聚合 | `--summary` |
| **I/O 延迟** | 按 fd/path/syscall 的延迟分布、慢调用阈值 | 事件聚合 | `--io-latency` / `--slow-us` |
| **网络汇总** | 网络 syscall 与 socket 连接/状态聚合 | 事件聚合 | `--net` |
| **进程/资源汇总** | clone/exec/wait/prlimit 等进程级 syscall 聚合 | 事件聚合 | `--process` |
| **证据级诊断** | 路径 miss 排行、慢 syscall、futex 等待、失败率（只输出有证据的） | 事件 + 状态 | `--diagnose` |
| **拒因归因** | 被拒 syscall 的 EPERM/EACCES 是否来自 seccomp、来自哪条规则 | `PTRACE_GET_SYSCALL_INFO` SECCOMP op | `--explain-deny` |
| **seccomp 过滤快路径** | 把 `--filter` 下沉内核，过滤集外 syscall 不再触发停顿 | seccomp-BPF + `PTRACE_O_TRACESECCOMP` | `--seccomp-bpf` |
| **seccomp 过滤器 dump** | 反汇编目标已装的 cBPF 过滤器 | `PTRACE_SECCOMP_GET_FILTER` | `--dump-seccomp` |
| **错误注入** | 给指定 syscall 注入 errno（改 `orig_rax`/`rax`） | entry/exit 寄存器篡改 | `--inject` |
| **信号 / 生命周期** | 信号投递停顿、线程/进程退出与被信号杀死事件 | waitpid 状态分类 | `--signals` / `--lifecycle` |

---

## 核心机制

```
┌──────────────────────────────────────────────────────────────────┐
│                          mini-strace                               │
│         ptrace syscall 事件源 + 状态关联 + 内核协作面               │
└──────────────────────────────────────────────────────────────────┘
   │
   ├─ 接管目标 ── launch:  fork + PTRACE_TRACEME + raise(SIGSTOP) + execvp
   │             attach:  PTRACE_SEIZE + PTRACE_INTERRUPT（枚举 /proc/<pid>/task 全线程）
   │
   ├─ 事件循环 ── waitpid(__WALL) → stop 分类:
   │             syscall-stop (SIGTRAP|0x80) / seccomp-stop (PTRACE_EVENT_SECCOMP)
   │             / ptrace-event (FORK/CLONE/EXEC) / signal-delivery / 退出
   │             按 tid 维护 entry/exit 配对，多线程/follow-fork 不串线
   │
   ├─ 读取信息 ── PTRACE_GET_SYSCALL_INFO（5.3+，优先）→ 回退 PTRACE_GETREGS
   │             process_vm_readv 读字符串/buffer/sockaddr，失败标 <unreadable> 不中断
   │
   ├─ 解码分层 ── raw 参数（兜底）→ 高频 syscall 参数 → flags/sockaddr/结构体
   │             损失容忍: 解不出保留 raw args/ret/errno 和读取失败原因
   │
   ├─ 状态关联 ── fd 表 (open/close/dup/socket/connect/accept, execve 清 CLOEXEC)
   │             VMA 区间 (mmap/munmap/mprotect/brk)  — 轻量推断, 标 inferred
   │
   ├─ 内核协作 ── seccomp-BPF 过滤下沉 / 错误注入 / seccomp 过滤器 dump / 拒因归因
   │
   └─ 输出聚合 ── 文本 (strace-like) / JSON Lines / summary / io-latency / net / 诊断
```

> 关键边界（README 显著位置）：ptrace 每个 syscall 至少**两次停顿**，会明显拖慢 tracee，适合调试/采样而非常态挂高吞吐进程。看到的是**内核 syscall ABI**（`open`→`openat`），不是 C 库函数；vDSO 调用（如部分 `clock_gettime`）走用户态不产生 syscall-stop，看不到不代表没发生。

---

## 快速开始

环境要求：Linux x86_64、内核 5.3+（`PTRACE_GET_SYSCALL_INFO`，否则回退 `GETREGS`）、GCC/Clang 支持 C++17、CMake 3.20+。

```bash
cd cpp-sys-labs/mini-strace
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
cd build && ctest --output-on-failure        # 全部用例应通过
```

构建产物（`mini-strace` 主程序 + 各 demo）位于 `build/`。

最小冒烟：

```bash
./build/mini-strace -- /bin/echo hello          # 跟踪一条命令的全部 syscall
./build/mini-strace --summary -- /bin/ls /tmp   # 只看 syscall 计数/耗时汇总
./build/mini-strace --json -- /bin/true | head  # JSON Lines 事件流
```

---

## 命令速查

```bash
BIN=./build/mini-strace

# 启动并跟踪（命令需要自己的 --flag 时用 -- 分隔）
$BIN -- ./demo arg1 arg2
$BIN --filter openat,read,write -- ./demo        # 只看指定 syscall
$BIN --summary -- ./demo                          # count/errors/total/avg/max，按总耗时排序
$BIN --json -- ./demo | jq                        # JSON Lines，机器可读
$BIN --state -- ./demo                            # 输出带 fd<path>/socket<peer>/mmap 区间
$BIN --follow-fork -- ./demo                      # 跟踪 fork/clone 子进程，带 [pid N] 前缀
$BIN --strings 128 -- ./demo                      # 字符串/buffer 最多读 128 字节

# attach 已有进程（受 ptrace 权限限制，Ctrl-C 默认 detach 不杀目标）
$BIN --pid 1234 --filter write --summary

# 分析模式
$BIN --io-latency --slow-us 2000 -- ./demo        # 按 fd/path/syscall 的 I/O 延迟，慢阈值 2ms
$BIN --net -- ./demo                              # 网络 syscall / socket 连接汇总
$BIN --process -- ./demo                          # clone/exec/wait/prlimit 进程级汇总
$BIN --diagnose -- ./demo                         # 证据级诊断：路径 miss/慢 syscall/futex/失败率
$BIN --signals --lifecycle -- ./demo              # 信号投递 + 线程/进程退出事件

# 内核协作面
$BIN --seccomp-bpf --filter openat -- ./demo      # 过滤下沉内核，集外 syscall 不再停顿
$BIN --dump-seccomp -- ./sandboxed_demo           # dump 目标 seccomp cBPF 过滤器
$BIN --explain-deny -- ./sandboxed_demo           # 把被拒 syscall 的 EPERM 归因到 seccomp 规则
$BIN --inject openat:error=ENOENT -- ./demo       # 给 openat 注入 ENOENT
$BIN --inject read:error=EINTR:when=3 -- ./demo   # 第 3 次 read 注入 EINTR，测重试逻辑

# 采样控制
$BIN --max-events 100 -- ./demo                   # 输出 100 个事件后 detach
$BIN --output trace.txt -- ./demo                 # 写文件（默认 stdout）
```

通用修饰：`--raw`（不解码，只输出十六进制参数）、`--output <file>`、`--help`（用法与权限说明）。完整选项见 `mini-strace --help`。

`--` 用法提示：被跟踪命令自己需要 `--xxx` 参数时，用 `mini-strace [本工具选项] -- <command> --xxx` 显式分隔。

退出码：`-- command` 模式默认透传 tracee 退出码，被信号杀死返回 `128+signal`；参数/权限/内部错误返回非 0 并在 stderr 给原因。

---
## 代码架构

### 目录结构

```
mini-strace/
├── CMakeLists.txt                  # 构建定义: mini_strace_core 静态库 + 主程序 + 各 demo + CTest;
│                                   #   mini_strace_warnings interface target 固化警告标志
├── README.md                       # 本文档
│
├── include/                        # 对外公共头 (库的 API 边界)
│   ├── mini_strace.hpp             # 数据模型契约: SyscallEvent / TraceOptions / TraceResult /
│   │                               #   FdContext / VmaContext / 各枚举; 所有模块围绕它工作
│   └── unique_fd.hpp               # RAII 文件描述符封装
│
├── src/                            # 全部实现
│   │   # ── 接管与事件循环 ────────────────────────────────────────────
│   ├── main.cpp                    # 入口: CLI 解析、模式分发、参数校验
│   ├── tracer.cpp                  # launch(fork+TRACEME+exec) / 顶层 run_trace 编排
│   ├── attach.cpp                  # attach: SEIZE/INTERRUPT、枚举 /proc/<pid>/task、setoptions
│   ├── trace_loop.cpp              # 事件循环核心: waitpid + stop 分类 + entry/exit 配对 + resume
│   ├── injection.cpp               # syscall 错误注入: entry 改 orig_rax、exit 改 rax
│   ├── seccomp.cpp                 # 构造/安装 seccomp-BPF 过滤器、dump 目标过滤器
│   │
│   │   # ── 读取与解码 ──────────────────────────────────────────────
│   ├── memory_reader.cpp           # process_vm_readv 读 tracee 内存 + PTRACE_PEEKDATA 回退
│   ├── syscall_table.cpp           # x86_64 syscall nr ↔ name 表 (生成后入库)
│   ├── decoder.cpp                 # 解码调度 + escape_text/escape_json + errno 格式化
│   ├── decode_file.cpp             # 路径 / open flags / AT_* / statx 解码
│   ├── decode_net.cpp              # sockaddr (AF_INET/INET6/UNIX) / iovec / msghdr 解码
│   ├── decode_process.cpp          # clone flags / clone3 / wait status / rlimit / exec 解码
│   ├── decode_poll_epoll.cpp       # poll/ppoll/select fd_set / epoll_event 解码
│   ├── decode_memory.cpp           # mmap/mprotect/mremap prot|flags 解码
│   ├── decode_seccomp.cpp          # seccomp 相关参数解码
│   │
│   │   # ── 状态关联与分析 ──────────────────────────────────────────
│   ├── state.cpp                   # 增量 fd 表 + VMA 区间模型 (enrich_before / apply)
│   ├── summary.cpp                 # 按 syscall 的 count/errors/total/avg/max 聚合
│   ├── io_latency.cpp              # 按 fd/path/syscall 的 I/O 延迟与慢调用
│   ├── net_trace.cpp               # 网络 syscall / socket 连接聚合
│   ├── process_trace.cpp           # 进程/资源 syscall 聚合
│   ├── deny_explainer.cpp          # 被拒 syscall 的 seccomp/权限 拒因归因
│   ├── lifecycle.cpp               # 线程/进程退出、被信号杀死事件
│   ├── event_pipeline.cpp          # 事件 mutate/observe 管线、EventSink 分发
│   │
│   └── output.cpp                  # 文本 (strace-like) + JSON Lines 渲染
│
├── demos/                          # 可复现的固定行为样本程序 (制造特定 syscall 序列供验证)
│   ├── hello_syscalls.cpp          # write/exit 最小 demo
│   ├── file_ops.cpp                # openat/read/write/close/ENOENT
│   ├── mmap_ops.cpp                # mmap/mprotect/munmap/brk
│   ├── fork_tree.cpp               # follow-fork
│   ├── socket_lifecycle.cpp        # connect/accept peer 关联
│   ├── network_trace.cpp           # 网络 syscall 综合
│   ├── poll_ops.cpp / epoll_ops.cpp  # poll/epoll 解码
│   ├── futex_wait.cpp              # futex 等待
│   ├── eintr_read.cpp              # 阻塞 read 被信号打断 / restart
│   ├── signal_delivery.cpp / signaled_exit.cpp  # 信号投递 / 被信号杀死
│   ├── exec_cloexec.cpp            # exec 后 close-on-exec fd 清理
│   ├── fd_state_edges.cpp / state_escape.cpp    # fd 状态边界 / 字段转义
│   ├── threaded_writes.cpp / attach_thread_on_input.cpp  # 多线程 / attach
│   ├── seccomp_errno.cpp           # 自装 seccomp 过滤器 → dump / 拒因归因
│   ├── io_latency.cpp              # I/O 延迟样本
│   ├── process_resource.cpp        # clone/wait/prlimit 样本
│   ├── openat2_ops.cpp             # openat2 / open_how
│   ├── syscall_loop.cpp           # 高频 getpid/write → benchmark + seccomp-BPF 快路径验证
│   └── exit_status.cpp             # 退出码透传
│
└── tests/
    ├── smoke.cpp                   # CTest: 固定 syscall 序列、filter、summary、状态模型
    ├── json_schema_smoke.sh        # JSON 事件 schema / seccomp / 拒因诊断断言
    └── benchmark_smoke.sh          # ptrace 开销 benchmark
```

> 编译产物默认输出到 `build/`。

### 模块职责

接管与事件循环：

| 文件 | 职责 |
| --- | --- |
| `main.cpp` | CLI 解析、模式分发、参数校验，不放业务逻辑 |
| `tracer.cpp` | launch 模式 `fork + PTRACE_TRACEME + execvp`，顶层 `run_trace` 编排 |
| `attach.cpp` | attach 模式 `PTRACE_SEIZE/INTERRUPT`，枚举 `/proc/<pid>/task` 全线程，`PTRACE_SETOPTIONS` |
| `trace_loop.cpp` | 事件循环核心：`waitpid(__WALL)` → stop 分类 → 按 tid entry/exit 配对 → 统一 resume |
| `injection.cpp` | syscall 错误注入：entry 改 `orig_rax` 为无效号、exit 改 `rax` 为 `-errno` |
| `seccomp.cpp` | 把 `--filter` 编译成 cBPF 安装到 tracee，dump 目标已装过滤器 |

读取与解码（损失容忍：解不出保留 raw）：

| 文件 | 职责 |
| --- | --- |
| `memory_reader.cpp` | `process_vm_readv` 读字符串/buffer，短读/截断/`<unreadable>` 兜底，`PEEKDATA` 回退 |
| `syscall_table.cpp` | x86_64 `nr ↔ name`，未知 syscall 输出 `sys_<nr>` |
| `decoder.cpp` | 解码调度 + `escape_text`/`escape_json` 转义 + errno 名称/消息 |
| `decode_file/net/process/poll_epoll/memory/seccomp.cpp` | 各域参数解码：路径/flags/sockaddr/iovec/clone/epoll/prot 等，不可信长度一律封顶 |

状态关联与分析（纯增量推断，标 `inferred`，不反向控制 ptrace）：

| 文件 | 职责 |
| --- | --- |
| `state.cpp` | fd 表（open/close/dup/socket/connect/accept，execve 清 CLOEXEC）+ VMA 区间模型 |
| `summary.cpp` | 按 syscall 聚合 count/errors/total/avg/max |
| `io_latency.cpp` | 按 fd/path/syscall 的 I/O 延迟与慢调用阈值 |
| `net_trace.cpp` | 网络 syscall 与 socket 连接/状态聚合 |
| `process_trace.cpp` | clone/exec/wait/prlimit 等进程级聚合 |
| `deny_explainer.cpp` | 被拒 syscall 的 EPERM/EACCES → seccomp 规则归因 |
| `lifecycle.cpp` | 线程/进程退出、被信号杀死事件 |
| `event_pipeline.cpp` | 事件 mutate→observe 管线、`EventSink` 分发（CLI / 库消费者共用） |
| `output.cpp` | 文本（strace-like）+ JSON Lines 渲染，只渲染不采集 |

### 关键数据模型

- **`SyscallEvent`**：一次 syscall 的完整视图 —— `pid/tid/sequence`、`nr/name`、`raw_args` + `decoded_args`、`enter_ns/exit_ns/duration_ns`、`raw_ret/is_error/errno_*`、可选 `fd_context`/`vma_context`/`seccomp_context`、`injected` 标志。
- **`ThreadState`**：按 tid 保存 `pending`（entry 暂存，待 exit 配对），多线程/follow-fork 不串线。
- **`FdContext` / `VmaContext`**：增量推断的 fd 画像与地址区间，标 `known`/`source`，明确不是内核真值。
- **`TraceOptions` / `TraceResult`**：跟踪配置与结果（事件数、退出码、信号）；`trace(options, EventSink&)` 是可复用库接口，CLI 与后续 `io-latency-tracer` 共用同一事件模型。

---

## 技术栈

- **语言**：C++17（`std::optional`、`std::array`、结构化绑定等）
- **构建**：CMake 3.20+，CTest 驱动冒烟与 schema/benchmark 脚本；`mini_strace_warnings` interface target 固化 `-Wall -Wextra -Wshadow`
- **编译器**：GCC / Clang（C++17）
- **零第三方依赖**：仅用标准库 + Linux 系统调用；JSON 输出自实现，测试用裸 `assert` + CTest + shell 断言，不引入测试框架

涉及的 Linux 内核接口（项目的核心学习价值所在）：

| 类别 | 接口 |
| --- | --- |
| 进程接管 | `fork` + `ptrace(PTRACE_TRACEME)` + `execvp`、`PTRACE_SEIZE` / `PTRACE_INTERRUPT` |
| syscall 跟踪 | `ptrace(PTRACE_SYSCALL)`、`PTRACE_GET_SYSCALL_INFO`（5.3+）、`PTRACE_GETREGS` 回退、`PTRACE_SETOPTIONS` |
| 事件等待 | `waitpid(__WALL)`、stop 分类（syscall-stop / `PTRACE_EVENT_*` / signal-delivery） |
| 内存读取 | `process_vm_readv`、`PTRACE_PEEKDATA` 回退 |
| 内核协作 | seccomp-BPF（cBPF + `PTRACE_O_TRACESECCOMP` + `PTRACE_EVENT_SECCOMP`）、`PTRACE_SECCOMP_GET_FILTER`、寄存器篡改注入 |
| 计时 | `clock_gettime(CLOCK_MONOTONIC)` 打 entry/exit 时间戳 |
| /proc | `/proc/<pid>/task`（线程枚举）、`/proc/<pid>/status`（tgid）、ptrace_scope 权限解释 |

C++ 工程实践：RAII（`UniqueFd`）封装内核资源、按 tid 隔离 pending 的状态机、解码与采集/输出分层、不可信长度封顶与 memcpy 前置守卫、读取失败 `<unreadable>` 降级不中断。

---

## Demos

`demos/` 下是一组制造固定 syscall 行为的样本程序，既是可复现示例也是 CTest fixture：

```bash
# 文件操作 + ENOENT
./build/mini-strace -- ./build/file_ops_demo

# 只看 write，并打印汇总
./build/mini-strace --filter write --summary -- ./build/hello_syscalls_demo

# follow-fork：看到 parent 和 child 两个 pid
./build/mini-strace --follow-fork -- ./build/fork_tree_demo

# socket 连接 peer 关联（--state）
./build/mini-strace --state --net -- ./build/socket_lifecycle_demo

# seccomp 拒因归因：被过滤器拦的 syscall 归因到规则
./build/mini-strace --explain-deny -- ./build/seccomp_errno_demo

# seccomp-BPF 快路径 benchmark：高频 getpid，只过滤 write
./build/mini-strace --seccomp-bpf --filter write -- ./build/syscall_loop_demo --syscall getpid --count 100000

# 错误注入：本应成功的 openat 返回 ENOENT
./build/mini-strace --inject openat:error=ENOENT -- ./build/file_ops_demo
```

| demo | 制造的行为 | 验证点 |
| --- | --- | --- |
| `hello_syscalls_demo` | write/exit | 最小事件流、退出码透传 |
| `file_ops_demo` | openat/read/write/close + ENOENT | 路径解码、errno |
| `socket_lifecycle_demo` | connect/accept | sockaddr 解码、peer 关联 |
| `fork_tree_demo` | fork 子进程 | `--follow-fork` 多 pid 前缀 |
| `eintr_read_demo` | 阻塞 read 被信号打断 | EINTR / restart_syscall 不错配 pending |
| `exec_cloexec_demo` | exec 后 CLOEXEC fd | 状态模型 exec 后清 fd |
| `seccomp_errno_demo` | 自装 seccomp 过滤器 | `--dump-seccomp` / `--explain-deny` 归因 |
| `syscall_loop_demo` | 高频 getpid/write | seccomp-BPF 快路径开销 benchmark |

---

## 使用场景与实战

```bash
BIN=./build/mini-strace
DEMO=./build              # demo 可执行与主程序同目录
```

### 场景 1：程序启动慢 / 找不到文件

**问题**：程序启动卡顿或报 `ENOENT`，怀疑在到处找配置/库/字体。

**复现**：`file_ops_demo` 打开一个不存在的路径。

```bash
$BIN --filter openat,newfstatat,access -- $DEMO/file_ops_demo
$BIN --diagnose -- $DEMO/file_ops_demo
```

**看什么**：事件流里每个 `openat` 带解码后的路径和 errno，`-1 ENOENT` 一眼可见；`--diagnose` 把 `ENOENT` 路径按前缀排行，直接点名「在哪个目录反复找不到」。

---

### 场景 2：网络连接卡住 / 连到了谁

**问题**：请求迟迟不返回，想知道卡在哪个 syscall、连的哪个 peer。

**复现**：`socket_lifecycle_demo` 建连。

```bash
$BIN --state --net -- $DEMO/socket_lifecycle_demo
```

**看什么**：`--state` 把 socket fd 标成 `connect(3<TCP 10.0.0.5:443>)`，`recvfrom` 卡住时一眼看到对端；`--net` 汇总 socket 连接与状态。`connect` 的 sockaddr 在 entry 解码，`accept` 的 peer 在 exit 解码。

---

### 场景 3：syscall 慢在哪 / I/O 延迟

**问题**：程序整体慢，想定位是哪个 fd、哪类 syscall 吃时间。

**复现**：

```bash
$BIN --summary -- $DEMO/io_latency_demo                 # 按 syscall 总耗时排序
$BIN --io-latency --slow-us 1000 -- $DEMO/io_latency_demo  # 按 fd/path 看慢调用
```

**看什么**：`--summary` 默认按 `total` 降序，一眼看到时间花在 `futex`/`read`/`write` 哪类；`--io-latency` 进一步按 fd/path 拆，`--slow-us` 标出超阈值的慢调用。耗时是「trace 视角」（含 ptrace 停顿），不等于纯内核执行时间。

---

### 场景 4：被 sandbox 拦截 —— 谁返回的 EPERM

**问题**：容器/沙箱里某 syscall 莫名 `EPERM` 或进程被 kill，怀疑 seccomp。

**复现**：`seccomp_errno_demo` 自装一个过滤器再触发被拦 syscall。

```bash
$BIN --dump-seccomp -- $DEMO/seccomp_errno_demo      # 看目标装了什么过滤器
$BIN --explain-deny -- $DEMO/seccomp_errno_demo      # 把 EPERM 归因到具体规则
```

**看什么**：`--dump-seccomp` 用 `PTRACE_SECCOMP_GET_FILTER` 反汇编目标的 cBPF；`--explain-deny` 在被拒事件上标 `blocked by seccomp`，回答「不是程序的错，是 sandbox 拦的」——这是 `strace` 不直接给的。

---

### 场景 5：测错误处理 —— 主动注入故障

**问题**：想验证程序对 `openat` 失败 / `read` 被 `EINTR` 打断时的重试/降级逻辑。

**复现**：

```bash
$BIN --inject openat:error=ENOENT -- $DEMO/file_ops_demo
$BIN --inject read:error=EINTR:when=3 -- ./your_program
```

**看什么**：注入事件标 `[injected ENOENT]`，本应成功的 `openat` 返回 `-ENOENT`，程序的错误分支被触发。机制是 entry 把 `orig_rax` 改成无效号让内核不执行、exit 把 `rax` 改成 `-errno`。`when=N` 只在第 N 次命中注入，适合测「第几次失败」。

---

### 场景 6：高频 syscall 进程 —— seccomp-BPF 快路径

**问题**：只关心某类 syscall，但目标是 `getpid/futex` 高频进程，纯过滤仍被双停顿拖慢。

**复现**：`syscall_loop_demo` 高频 getpid。

```bash
$BIN --filter write -- $DEMO/syscall_loop_demo --syscall getpid --count 100000              # 用户态过滤
$BIN --seccomp-bpf --filter write -- $DEMO/syscall_loop_demo --syscall getpid --count 100000 # 内核过滤
```

**看什么**：两者输出相同（只有 write），但 `--seccomp-bpf` 把过滤下沉内核，`getpid` 根本不触发停顿——对高频场景是数量级的开销差。这正是 `strace --seccomp-bpf` 的同款机制。

---

### 场景 7：attach 已有进程

**问题**：进程已经在跑，想挂上去看它在干什么。

**复现**：

```bash
./build/syscall_loop_demo --syscall write --count 100000 & pid=$!
$BIN --pid $pid --filter write --summary
kill $pid 2>/dev/null
```

**看什么**：`--pid` 用 `PTRACE_SEIZE` attach 并枚举所有线程；Ctrl-C 默认 `PTRACE_DETACH` 不杀目标。权限不足（Yama `ptrace_scope` / 非同 uid / 缺 `CAP_SYS_PTRACE`）时会给可操作提示。

---

## 边界与权限

- **架构**：当前仅支持 Linux x86_64；其他架构 syscall 号/参数寄存器/返回值规则不同，需另写适配层。
- **性能**：ptrace 每个 syscall 至少两次停顿，显著拖慢 tracee，适合调试/短时采样，不适合常态挂高吞吐进程。需要近零开销请用 eBPF/ftrace/perf。
- **attach 权限**：`--pid` 受 ptrace 权限模型限制，可能被 Yama `ptrace_scope`、uid、缺 `CAP_SYS_PTRACE` 拦住；失败时给提示。
- **观测盲区**：看到的是内核 syscall ABI（`open`→`openat`、`exit`→`exit_group`）；vDSO 调用（部分 `clock_gettime/gettimeofday`）走用户态不产生 syscall-stop；被信号打断的 syscall 可能出现 `restart_syscall`。
- **解码降级**：`process_vm_readv` 读字符串可能失败，输出 `<unreadable:EFAULT>` 是正常边界；未知 syscall 走 raw 输出。
- **状态模型**：fd/VMA/socket 上下文是**增量推断**，attach 前的状态依赖 `/proc` seed，标 `known=false`/`inferred`，不是内核真值；完整 VMA 模型（精确 split/merge/RSS）见 `mem-map-viewer`。
- **seccomp-BPF**：需要在 tracee 侧 `PR_SET_NO_NEW_PRIVS` 后安装；cBPF 只能按 syscall 号/常量参数过滤，路径等字符串过滤仍回用户态。
- **正确性对标**：与 `strace` 的固定行为做对标测试，环境缺 `strace` 时 skip，不把「没跑对标」说成「已通过对标」。

---

## 许可说明

知识星球：“奔跑中cpp / c++” 所有，

阿甘微信：LLqueww

商业使用前请联系我方授权 一旦发现侵权行为，将依法追究法律责任

（对于公司法律事务已有对接律师，敬请告知）

