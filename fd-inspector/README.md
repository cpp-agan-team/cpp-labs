# fd-inspector

`fd-inspector` 是一个 Linux 文件描述符 / socket 诊断工具。用 `pidfd_open` + `pidfd_getfd` 把目标进程的 fd **复制**到本进程，再用普通fd 系统调用（`fstat`/`fstatfs`/`fcntl`）直接审问内核对象；socket 详情走`NETLINK_SOCK_DIAG` 二进制协议（`ss` 的同款机制），按 inode 反查回 fd。

它的定位不是替代 `lsof`——快速人工排查仍然用 `lsof -p <pid>`。它专注于 `lsof`/`ss`
单独做不到的事：**fd 泄漏检测（带趋势判定与归因）、socket 连接状态关联、结构化
JSON 输出、容器/服务自检**，并附带一个可选的 **eBPF 泄漏追踪器**，把"周期采样推断"
升级为"事件级因果定位"。

> 本项目属于 `cpp-sys-labs`（C++ Linux 系统编程实验室）第 1 层「主动观测」工具，
> 对标 `lsof` + `ss`。

## 能检测到什么

一次 `fd-inspector --pid <pid>` 会对目标进程的每个 fd 给出：

| 维度 | 具体内容 | 数据来源 |
| --- | --- | --- |
| **fd 基本信息** | fd 号、类型、target 路径、inode、设备号、文件系统类型、flags | `fstat`/`fstatfs`/`fcntl` 或 `/proc` |
| **fd 类型识别** | file / dir / pipe / fifo / socket / char / block / **epoll / eventfd / timerfd / signalfd / inotify / fanotify** / anon | stat + target + fdinfo |
| **socket 连接** | 协议、本地/远端地址、TCP 状态（ESTABLISHED/CLOSE_WAIT/…）、收发队列、socket 内存、拥塞算法、RTT/cwnd/重传 | `NETLINK_SOCK_DIAG` |
| **UNIX socket** | peer inode、路径、队列长度、内存 | `unix_diag` |
| **epoll 内部** | 该 epoll 正在监视哪些 fd、事件掩码 | `fdinfo` |
| **事件 fd 状态** | eventfd 计数、timerfd ticks、signalfd 信号掩码 | `fdinfo` |
| **监控 fd** | inotify watch 列表、fanotify mark | `fdinfo` |
| **挂载信息** | 挂载点、挂载根、mount id | `mountinfo` |
| **删除文件** | 标记 `(deleted)` 且报告占用字节大小 | readlink + stat |

`--leak-check` 模式额外给出：**是否疑似泄漏、是否单调增长、各类型增量、新增的具体
target、CLOSE_WAIT 计数、按 (类型/target) 分桶的增长榜**。

## 项目架构

关注点分离：**CLI 解析 / 核心采集 / 输出格式化**互不耦合。核心采集逻辑按职责拆成
多个翻译单元，统一编进静态库 `fd_inspector_core`，可被 CLI、测试和其他程序 `#include`。

```
  命令行
    │  InspectOptions
    ▼
 main.cpp ───────────────► fd_inspector_core （静态库）────────────► 表格 / JSON
 CLI 解析/分发              ┌────────────────────────────────┐        output.cpp
 once/watch/leak-check     │ fd_inspector.cpp  顶层编排        │
                           │   inspect_pid（枚举/复制/合并）   │
                           │ proc_scan.cpp     /proc 采集      │
                           │   pidfd/fd枚举/fdinfo/io_uring    │
                           │ socket_diag.cpp   socket 反查     │
                           │   NETLINK_SOCK_DIAG/netns        │
                           │ fd_util.cpp       工具/解析/stat  │
                           │ leak_detector.cpp check_leak     │
                           └────────────────────────────────┘
                              共享数据模型：FdEntry / SocketInfo / LeakReport
```

数据流：`main` 构造 `InspectOptions` → `inspect_pid` 枚举 `/proc/<pid>/fd`、逐个复制
并审问、合并 sock_diag / fdinfo / mountinfo，产出 `std::vector<FdEntry>` → `output`
渲染成表格或 JSON。`--leak-check` 由 `check_leak` 多次调用 `inspect_pid` 做时间序列
采样与归因，产出 `LeakReport`。

## 代码文件结构

```
fd-inspector/
├── CMakeLists.txt              # 构建：核心库、CLI、demo、测试、可选 eBPF
├── include/                    # 对外公共头
│   ├── fd_inspector.hpp        #   公共 API 与数据模型（FdEntry/SocketInfo/LeakReport/枚举）
│   └── unique_fd.hpp           #   RAII fd 封装
├── src/
│   ├── fd_inspector_internal.hpp  # 内部头：detail 命名空间的工具与采集函数声明
│   ├── fd_inspector.cpp        #   顶层编排：inspect_pid（枚举/复制/合并）+ type_name
│   ├── fd_util.cpp             #   基础工具：字符串/解析、stat→FdEntry、类型识别、错误/权限提示
│   ├── proc_scan.cpp           #   /proc 采集：pidfd 系统调用、fd 枚举、fdinfo/mountinfo、io_uring statx
│   ├── socket_diag.cpp         #   socket：NETLINK_SOCK_DIAG（inet/unix）、netns setns、本地兜底
│   ├── leak_detector.cpp       #   check_leak：多点采样、单调性判定、按类型/target 归因
│   ├── output.cpp              #   表格与 JSON 渲染
│   └── main.cpp                #   CLI：参数解析校验、once/watch/leak-check 分发
├── demos/                      # 可复现的事故场景（下面"使用场景"逐个讲怎么跑）
│   ├── fd_leak.cpp             #   循环 open 不 close —— 文件 fd 泄漏
│   ├── fd_socket_leak.cpp      #   accept 后不 close —— TCP 连接泄漏 / CLOSE_WAIT
│   ├── fd_anon_state.cpp       #   epoll/eventfd/timerfd/signalfd/inotify —— 匿名 fd 内部状态
│   ├── fd_deleted_file.cpp     #   unlink 后仍持有句柄 —— 删除文件仍占磁盘
│   ├── fd_many.cpp             #   一次开 N 个 fd —— 大进程扫描 / io_uring 加速
│   ├── fd_sources.cpp          #   各类 fd 综合（pipe/memfd/io_uring/close_range）
│   └── fd_exec.cpp             #   execve 后 close-on-exec 行为
├── tests/
│   └── smoke.cpp               # 冒烟测试：fork 已知行为，断言类型/socket/inotify/fallback
└── ebpf/                       # 可选 eBPF 泄漏追踪器（默认不编译）
    ├── fd_events.h             #   内核/用户态共享的事件结构与枚举
    ├── fd_leak_tracer.bpf.c    #   内核侧：syscall tracepoint + 用户栈 + ringbuf
    └── fd_leak_tracer.cpp      #   用户侧：libbpf + ELF 符号 + addr2line
```


## 编译

本项目是独立 CMake 工程，**在 `fd-inspector/` 目录下直接构建**即可（也可被上层仓库通过
`add_subdirectory` 引入）：

```bash
cd cpp-sys-labs/fd-inspector          # 进入本项目目录
sudo apt install -y liburing-dev
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
cd build && ctest --output-on-failure        # 跑测试
```

要求：CMake ≥ 3.20，C++17（GCC 12+ / Clang 15+），Linux 内核 ≥ 5.6（`pidfd_getfd`）。

为方便下文，先定义一个变量指向编译出的二进制（独立构建时产物就在 `build/` 根下）：

```bash
BIN=./build/fd-inspector
DEMO=./build              # demo 可执行所在目录（与 fd-inspector 同级）
```

`cmake --build build` 会**一并编译所有 demo**（产物和 `fd-inspector` 同目录）。若只想
单独编译某个 demo，用 `--target`，例如：

```bash
cmake --build build --target fd_leak_demo     # 只编译 demos/fd_leak.cpp
```

下表是场景与 demo 源文件的对应关系：

| 场景 | demo 源文件 | 编译产物 | 检测重点 |
| --- | --- | --- | --- |
| 1 文件 fd 泄漏 | `demos/fd_leak.cpp` | `fd_leak_demo` | `--leak-check` 趋势判定 + 归因 |
| 2 匿名 fd 状态 | `demos/fd_anon_state.cpp` | `fd_anon_state_demo` | epoll/eventfd/timerfd/inotify 内部状态 |
| 3 连接泄漏 | `demos/fd_socket_leak.cpp` | `fd_socket_leak_demo` | CLOSE_WAIT 关联 + tcp_info |
| 4 close-on-exec | `demos/fd_exec.cpp` | `fd_exec_demo` | exec 前后快照对比 |
| 5 删除文件占盘 | `demos/fd_deleted_file.cpp` | `fd_deleted_file_demo` | `(deleted)` + 占用字节 |
| 6 大量 fd / 加速 | `demos/fd_many.cpp` | `fd_many_demo` | `--io-uring` + `--max-fd 0` |
| （综合）各类 fd | `demos/fd_sources.cpp` | `fd_sources_demo` | pipe/memfd/io_uring/close_range |

## 使用场景与实战

### 场景 1：文件描述符泄漏（`Too many open files`）

**问题**：服务跑久了报 `EMFILE / Too many open files`，怀疑某处 open 了不 close。

**编译并复现**：`demos/fd_leak.cpp` 每 200ms open 一个文件且从不 close，模拟泄漏。

```bash
cmake --build build --target fd_leak_demo     # 编译该 demo
$DEMO/fd_leak_demo &                          # 后台启动，会打印自己的 pid
pid=$!
$BIN --pid $pid --leak-check 5                # 采样 5 秒，观察 fd 是否单调增长
kill $pid
```

**看什么**：看 verdict 是不是 `suspected fd leak`、`monotonic=yes`，再看
`growth_buckets` 里增长最多的那一行——它直接点名是哪个 target 在涨：

```
suspected fd leak: fd counts grew monotonically during the sample window
first_total=12 last_total=37 file_growth=25 ... monotonic=yes
new_targets:
  file:/tmp/fd_leak_demo_file
growth_buckets:
  +25 file:/tmp/fd_leak_demo_file        ← 直接定位到泄漏的文件
```

检测到泄漏时**退出码为 2**（无泄漏为 0），可在脚本/CI 里 `echo $?` 断言。

---

### 场景 2：识别各种"匿名" fd（epoll / eventfd / timerfd / signalfd / inotify）

**问题**：`lsof` 把 epoll、eventfd、timerfd、inotify 这些都显示成 `anon_inode`，
看不出具体是什么、内部状态如何。

**编译并复现**：`demos/fd_anon_state.cpp` 创建 eventfd(初值7)、epoll(监视该 eventfd)、
timerfd(60s 定时)、signalfd(监听 SIGUSR1)、inotify(监视一个临时目录)，持有 30 秒。

```bash
cmake --build build --target fd_anon_state_demo
$DEMO/fd_anon_state_demo &           # 打印 pid
pid=$!
$BIN --pid $pid --json | jq          # 在 30 秒窗口内检测
kill $pid 2>/dev/null
```

**看什么**：看每个 anon fd 的 type 列是否被识别成具体类型，以及尾部带出的内部状态字段：

```
eventfd    ... eventfd_count=7              ← 当前计数
epoll      ... epoll_targets=1              ← 该 epoll 正在监视 1 个 fd
timerfd    ... timerfd_ticks=0
signalfd   ... sigmask=...                  ← 监听的信号掩码
inotify    ... inotify_watches=1            ← watch 数量（排查 watch 泄漏）
```

JSON 模式下还能展开 `epoll_targets`（具体监视哪些 fd）、`inotify_watches`（每个 watch
的 wd/inode/mask）。想看更杂的组合（含 memfd、io_uring、close_range）就编译运行
`fd_sources_demo`（源文件 `demos/fd_sources.cpp`）。

---

### 场景 3：TCP 连接泄漏 / CLOSE_WAIT 堆积

**问题**：连接数只增不减，怀疑代码 accept 后忘了 close，表现为大量 `CLOSE_WAIT`。

**编译并复现**：`demos/fd_socket_leak.cpp` 起一个 listener，不断 accept 新连接却从不
close，模拟连接泄漏。

```bash
cmake --build build --target fd_socket_leak_demo
$DEMO/fd_socket_leak_demo &          # 打印 pid 和监听端口
pid=$!
$BIN --pid $pid --socket             # 只看 socket，能看到越来越多连接
$BIN --pid $pid --leak-check 6       # 采样判定连接泄漏
$BIN --pid $pid --socket --json | jq '.[] | select(.socket.state=="CLOSE_WAIT")'
kill $pid 2>/dev/null
```

**看什么**：

```
socket   TCP 127.0.0.1:8080 -> 127.0.0.1:51234 CLOSE_WAIT src=diag [rtt=312us cwnd=10 retrans=0]
```

- 看每条连接的 **state（重点关注 CLOSE_WAIT 数量）、两端地址、RTT、拥塞窗口、重传**
  （`/proc/net/tcp` 不提供后面这些）。
- `--leak-check` 下，若 **socket 数增长 + 出现 CLOSE_WAIT**，verdict 明确写
  `suspected connection leak`——这是 `lsof`（管 fd）和 `ss`（管 socket）分开看都关联不出来的结论。

---

### 场景 4：execve 后哪些 fd 被 close-on-exec 关掉了

**问题**：子进程 exec 后行为异常，想确认哪些 fd 被 `O_CLOEXEC` 自动关闭、哪些被继承。

**编译并复现**：`demos/fd_exec.cpp` 先 open 一个 `O_CLOEXEC` 文件，2 秒后
`execvp("sleep")`。exec 前该 fd 在，exec 后应被自动关闭。

```bash
cmake --build build --target fd_exec_demo
$DEMO/fd_exec_demo &
pid=$!
$BIN --pid $pid                      # 在 exec 前（前 2 秒）检测：能看到 /tmp/fd_exec_demo_file
sleep 3
$BIN --pid $pid                      # exec 成 sleep 后：该 CLOEXEC fd 已消失
kill $pid 2>/dev/null
```

**看什么**：对比前后两次输出的 fd 列表——确认带 `O_CLOEXEC` 的 `/tmp/fd_exec_demo_file`
在 exec 后从表中消失，说明继承/关闭语义符合预期（排查"子进程继承了不该继承的 fd"）。

---

### 场景 5：删除但仍占磁盘的文件（"磁盘满了，du 却找不到"）

**问题**：`df` 显示磁盘满，但 `du` 找不到大文件——经典原因是某进程还**持有一个已被
`unlink` 删除的文件句柄**，空间要等进程关闭 fd 才释放。

**编译并复现**：`demos/fd_deleted_file.cpp` 写一个 8MB 临时文件、`unlink` 删掉它、但
保持 fd 打开 30 秒。

```bash
cmake --build build --target fd_deleted_file_demo
$DEMO/fd_deleted_file_demo &
pid=$!
$BIN --pid $pid --json | jq '.[] | select(.deleted)'
kill $pid 2>/dev/null
```

**看什么**：筛 `deleted=true` 的条目，看它的 `size` 字段——即该删除文件仍占的字节数：

```
file   /tmp/fd-deleted-file-xxxxxx (deleted)   size=8388608
```

明确标记 `(deleted)` 并**报告占用字节数**（这里 8388608 = 8MB）——直接量化"是哪个进程
的哪个删除文件在吃磁盘"，比单纯标记删除有用得多。

---

### 场景 6：大量 fd 的进程 / io_uring 加速扫描

**问题**：要检测一个开了成千上万 fd 的进程，想加速元数据获取。

**编译并复现**：`demos/fd_many.cpp` 默认开 512 个 fd（可传参，如 `fd_many_demo 5000`），
持有 30 秒。

```bash
cmake --build build --target fd_many_demo
$DEMO/fd_many_demo 2000 &
pid=$!
$BIN --pid $pid --max-fd 0 --io-uring --json | jq 'length'   # --max-fd 0 自动取 RLIMIT 上限
kill $pid 2>/dev/null
```

**看什么**：用 `jq 'length'` 看返回的 fd 条目数应约等于 demo 打印的 `held=N`（加上进程
自带的 0/1/2 等）。这里关注的是两个能力：`--io-uring` 用 liburing 批量提交 `statx`，对
超大 fd 表的元数据获取做并发加速；`--max-fd 0` 让扫描上界自动取自 `RLIMIT_NOFILE`
而非写死 65536。

---

### 场景 7：实时监控 fd 变化

**问题**：想盯着一个进程，实时看它 fd 涨没涨。

**复现**：本场景无专属 demo，直接配合场景 1 的 `fd_leak_demo`（持续泄漏）观察最直观：

```bash
$DEMO/fd_leak_demo & pid=$!
$BIN --pid $pid --watch --interval-ms 500       # 每 500ms 刷新一次，Ctrl-C 退出
kill $pid
```

**看什么**：盯着 fd 列表行数随刷新不断变长，即可肉眼确认泄漏正在发生。

---

### 场景 8：容器 / distroless 环境自检

**问题**：精简容器里没装 lsof/ss/strace，又要排查 fd/socket 问题。

**复现/用法**：本场景无专属 demo，直接把编译好的 `fd-inspector` 拷进容器使用：

```bash
$BIN --pid 1 --json        # 容器内 PID 1 通常就是主进程
```

**看什么 / 为什么能用**：

- fd-inspector 是**静态友好的单二进制**，丢进容器即可用，无需容器内有任何诊断工具。
- socket diag 在**目标进程的 network namespace** 内执行（`setns`），所以容器里看到的
  socket 视图是正确的，不会因为跨 netns 而把宿主机或别的容器的连接算进来。
- 重点关注 socket 条目的 `src=diag`（说明数据来自目标 netns 的 sock_diag）和连接状态。

## 命令行参数

| 参数 | 说明 |
| --- | --- |
| `--pid <n>` | 目标进程 pid（必填） |
| `--json` | 输出 JSON 而非表格（接 `jq`/监控/CI） |
| `--socket` | 只显示 socket 类型的 fd |
| `--max-fd <n\|0>` | 扫描 fd 号上界；`0` = 由 `RLIMIT_NOFILE` 自动推导 |
| `--watch [--interval-ms <n>]` | 周期刷新（默认 1000ms），Ctrl-C 退出 |
| `--leak-check <秒>` | 泄漏检测采样窗口，疑似泄漏时退出码 `2` |
| `--proc-fallback` | 强制走 `/proc` 兼容路径，不复制 fd |
| `--io-uring` | 用 liburing 批量 `statx` 预取元数据（加速大进程） |

退出码：`0` 正常 / 无泄漏；`2` 检测到疑似泄漏；`1` 参数或运行错误。

## 权限说明

`pidfd_getfd` 受 ptrace 权限模型约束。检查**别的用户**或受限进程时，可能需要 root
或 `CAP_SYS_PTRACE`；若 `kernel.yama.ptrace_scope` 收紧，工具会**自动降级**到 `/proc`
兼容路径，并在 stderr 打印可操作提示（如尝试 root，或调整 `ptrace_scope`）。降级后
仍能输出 fdinfo / mountinfo / stat / socket diag，只是拿不到"复制 fd 直接审问"的部分细节。

检查自己的进程不需要特殊权限：

```bash
$BIN --pid $$          # 检查当前 shell，随时可跑
```

## 可选：eBPF 泄漏追踪器（事件级根因定位）

当采样推断（场景 1）不足以定位"泄漏的 fd 是在哪行代码打开的"时，用 `fd-leak-tracer`：
它挂 syscall tracepoint，记录每次 fd 分配/关闭事件，并在分配时抓**用户态调用栈**，
把泄漏直接落到源码位置。独立目标，默认不编译（需要 BPF 内核、libbpf、clang/LLVM、
BTF、root/CAP_BPF）。

```bash
cmake -B build-ebpf -DCMAKE_BUILD_TYPE=Debug -DFD_INSPECTOR_ENABLE_EBPF=ON
cmake --build build-ebpf -j$(nproc)

D=./build-ebpf
$D/fd_leak_demo & pid=$!
sudo $D/fd-leak-tracer --pid "$pid" --seconds 5 \
     --bpf-object $D/fd_leak_tracer.bpf.o --verbose
kill "$pid"
```

## 技术栈

- **语言/标准**：C++17（RAII、`std::optional`、移动语义）
- **构建**：CMake ≥ 3.20、CTest、pkg-config
- **Linux 系统接口**：`pidfd_open` / `pidfd_getfd`、`fstat`/`fstatfs`/`fcntl`、
  `NETLINK_SOCK_DIAG`（`inet_diag` / `unix_diag`）、netlink 变长 `rtattr` 解析、
  `setns` + network namespace、`/proc` fdinfo/mountinfo、`io_uring`（liburing）、
  `getsockopt(TCP_INFO)`、`prlimit`
- **eBPF（可选）**：libbpf + CO-RE、syscall tracepoint、ringbuf、stack trace map、
  ELF 符号解析（libelf）、addr2line、`/proc/<pid>/maps` 偏移还原

## 面试介绍

> 开发 **fd-inspector**：一个 Linux fd/socket 诊断工具。
> 用 `pidfd_open`/`pidfd_getfd` 把目标进程的文件描述符复制到本进程，再用
> `fstat`/`fcntl`/`getsockopt` 直接审问借来的 fd。通过解析二进制 `NETLINK_SOCK_DIAG`
> （inet_diag/unix_diag）协议还原 socket 状态——含 TCP RTT、拥塞窗口、重传、socket
> 内存——并按 inode 反查关联回 fd。借助 `setns` 实现 network namespace 感知，支持容器
> 内省。实现了基于趋势的 fd 泄漏检测（单调增长采样 + 按类型/target 归因）、受限
> `ptrace_scope` 下的 `/proc` 优雅降级、可选 `io_uring` 批量 `statx`、以及结构化 JSON
> 输出。以及 eBPF/libbpf 泄漏追踪器，可把泄漏定位到分配它的调用栈。


## 许可说明

知识星球： “奔跑中cpp / c++” 所有 ，

阿甘微信：LLqueww

商业使用前请联系我方授权 一旦发现侵权行为，将依法追究法律责任

（对于公司法律事务已有对接律师，敬请告知）

