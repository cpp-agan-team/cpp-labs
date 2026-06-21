# mem-map-viewer

> Linux 进程虚拟内存观测工具集 —— 从 VMA 结构、页级驻留、页故障、硬件性能到容器内存压力的分层观测。

`mem-map-viewer` 不是 `pmap -X` 的复刻。`pmap` 给你一张「当前有哪些映射」的静态快照，本工具回答的是 `pmap`/`top` 答不了的问题：**这段内存是谁、在什么时刻映射的？映射了但真正用了多少页？哪段访问代价最高？整个进程组离 OOM 还有多远？**

工具按观测粒度分成五层，每层用一个专门的内核接口，多数层无需 ptrace 权限、可嵌入服务在生产环境运行。

---

## 目录

- [它能解决什么](#它能解决什么)
- [五层架构](#五层架构)
- [快速开始](#快速开始)
- [命令速查](#命令速查)
- [代码架构](#代码架构)
- [技术栈](#技术栈)
- [Demos](#demos)
- [使用场景与实战](#使用场景与实战)
- [权限与边界](#权限与边界)
- [面试介绍](#面试介绍)
- [许可说明](#许可说明)

---

## 它能解决什么

| 场景 | 典型信号 | 本工具能回答 |
| --- | --- | --- |
| C++ 服务内存持续上涨 | VIRT/RSS 长期增长 | 增长来自 heap `brk`、匿名 `mmap`、文件映射、线程栈还是共享库 |
| mmap 泄漏 | VIRT 很大、RSS 也涨 | 哪些 `mmap` 没有对应 `munmap`，大小和来源是什么 |
| 过度预分配 | 映射很大但 RSS 不高 | 用 `mincore` 给出「映射 1G 实际只驻留 2M」的页级真相 |
| JIT / 权限切换排查 | 出现 rwx 或频繁 mprotect | 哪段地址被 `mprotect` 改过权限、什么时候改的 |
| 内存访问慢 | RSS 不高但访问吃力 | 用 PMU 采样把 TLB/cache miss 归因到具体 VMA |
| 写热点分析 | 想知道哪些页真正被写过 | `clear_refs` + `pagemap` soft-dirty 位定位写过的页 |
| 容器 OOM 预警 | pod 内存接近 limit | cgroup v2 `memory.*` + PSI 给出压力指标和 OOM 风险分 |
| 修复回归验证 | 怕泄漏复发 | snapshot `--diff` + `--growth-check` 线性趋势判定 |

只想临时看一次当前映射时，`pmap -X <pid>` 更快。本工具的价值在**事件流、归因、页级真相和可复现诊断**。

### 一次调用能观测到什么

针对一个目标进程 / 地址范围，按所选模式给出：

| 维度 | 具体内容 | 数据来源 | 触发参数 |
| --- | --- | --- | --- |
| **VMA 快照** | 每段映射的区间、权限、类型、来源 path/inode/dev、RSS/PSS、provenance 来源标记 | `/proc/maps`+`smaps` / 事件流重建 | `--pid` / `--snapshot` |
| **VMA 事件流** | mmap/munmap/mprotect/brk/mremap 的参数、返回地址、成功标志、时序 | `ptrace` + seccomp-BPF | `--trace --events` |
| **聚合归因** | 按 region kind + source 聚合大小/RSS，定位增长来自 heap/anon/file/stack/lib | 快照聚合 | `--summary` |
| **快照 diff** | 两份快照按 kind/source 的 size/RSS/count 增量 | JSON 快照对比 | `--diff` |
| **页级驻留** | 每段 VMA 的驻留页数、驻留率（映射 vs 真正在物理内存） | `mincore` / `smaps` 近似 | `--residency` |
| **页故障流** | 首次访问 / 写保护页故障的地址、读写类型、时刻 | `userfaultfd` | `--uffd-demo` |
| **访问热点** | 按 VMA 聚合的 dTLB/cache miss 采样、丢样数、热点 IP | `perf_event_open` | `--perf-sample` |
| **页标志/状态** | present/swapped/soft-dirty/exclusive/PFN、anon/THP/LRU/dirty/slab | `pagemap`+`kpageflags` | `--pages` / `--page-flags` |
| **NUMA 分布** | 指定范围内页所在 NUMA node、per-page 错误状态 | `move_pages` | `--numa` |
| **资源上限** | RLIMIT_AS/DATA/STACK/MEMLOCK/RSS | `prlimit` | `--limits` |
| **容器内存健康** | cgroup 用量/上限、anon/file、PSI some/full、OOM 风险分 | cgroup v2 + PSI | `--cgroup` |
| **趋势判定** | 多采样单调性 + 线性回归斜率/R² + 增长分桶 | 时间序列采样 | `--growth-check` |
| **真值对账** | 观测快照 vs `/proc/maps` 的 missing/extra/metadata 差异 | reconcile | `--reconcile` |
| **跨层诊断** | 低驻留浪费 / 访问热点 / cgroup 压力 / limit 逼近 → 可读 insight | correlate 联合分析 | `--insights` |

---

## 五层架构

```
┌──────────────────────────────────────────────────────────────────┐
│                          mem-map-viewer                            │
│              分层进程内存观测工具集 (五层各司其职)                 │
└──────────────────────────────────────────────────────────────────┘
   │
   ├─ Layer 1  VMA 结构层 —— 地址空间有哪些映射、怎么变的
   │    机制: ptrace(PTRACE_SYSCALL) + seccomp-BPF 过滤 + /proc/maps seed
   │    产物: mmap/munmap/mprotect/brk/mremap 事件流、区间 split/merge、diff
   │
   ├─ Layer 2  页级驻留层 —— 映射的页里哪些真在物理内存
   │    机制: mincore(2)  (跨进程退化为 smaps RSS 近似)
   │    产物: 每个 VMA 的驻留率、冷热分布
   │
   ├─ Layer 3  页故障捕获层 —— 哪个页在什么时刻被首次访问/写
   │    机制: userfaultfd(2)  (MISSING / WP 双模式)
   │    产物: 页故障事件流 (地址 + 读写 + 时刻)
   │
   ├─ Layer 4  硬件性能层 —— 哪段内存访问代价最高
   │    机制: perf_event_open(2) + PMU ring buffer
   │    产物: 按 VMA 聚合的 dTLB/cache miss 采样、丢样统计
   │
   └─ Layer 5  容器压力层 —— 进程组整体内存健康、离 OOM 多远
        机制: cgroup v2 memory.* + PSI (memory.pressure)
        产物: 用量/上限、压力指标、OOM 风险评分

   ┌─ 进阶页级探针 (Layer 2-4 的底层补充) ──────────────────────────┐
   │  pagemap   读 /proc/pid/pagemap: present/swapped/soft-dirty/PFN  │
   │  page-flags 经 PFN 读 /proc/kpageflags: anon/THP/LRU/dirty/slab  │
   │  numa      move_pages 查页所在 NUMA node                         │
   │  clear-refs 写 /proc/pid/clear_refs 建立 soft-dirty 观测基线     │
   │  limits    prlimit 读 RLIMIT_AS/STACK/... 作为诊断上下文         │
   │  reconcile 用户态观测快照 vs /proc/maps 真值对账                 │
   └──────────────────────────────────────────────────────────────────┘
```

各层的权限与开销特性（决定能否上生产）：

| Layer | 机制 | 需 ptrace 权限 | 需 root/CAP | 开销 | 可上生产 |
| --- | --- | --- | --- | --- | --- |
| 1 VMA 结构 | ptrace + seccomp-BPF | 是（attach/trace 时） | 否 | 高 | 否 |
| 2 页级驻留 | mincore | 否 | 否 | 低 | 是 |
| 3 页故障 | userfaultfd | 否（自进程注册） | 视策略 | 中 | 视场景 |
| 4 硬件性能 | perf_event_open | 否 | 受 `perf_event_paranoid` 约束 | 低（采样） | 是 |
| 5 容器压力 | cgroup/PSI | 否 | 否（读 cgroupfs） | 极低 | 是 |

> 核心理念：Layer 1（ptrace）是事件流主线但会拖慢 tracee；Layer 2-5 多数无权限门槛、开销低，正好补上 Layer 1「不能挂线上」的硬伤。

---

## 快速开始

环境要求：Linux x86_64、内核 5.3+（`PTRACE_GET_SYSCALL_INFO`）、GCC/Clang 支持 C++17、CMake 3.20+。

```bash
cd cpp-sys-labs/mem-map-viewer
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
cd build && ctest --output-on-failure        # 全部用例应通过
```

构建产物（`mem-map-viewer` 主程序 + 各 demo）位于 `build/`，已被 `.gitignore` 忽略。

最小冒烟：

```bash
./build/mem-map-viewer --pid $$ --summary       # 看当前 shell 的 VMA 按类型聚合
./build/mem-map-viewer --pid $$ --residency      # 看各区域驻留率
./build/mem-map-viewer --cgroup self --psi       # 看自身 cgroup 内存压力
```

---

## 命令速查

```bash
BIN=./build/mem-map-viewer

# Layer 1: VMA 结构
$BIN --pid $$ --summary                          # 当前快照按 region/source 聚合
$BIN --pid $$ --json > before.json               # 导出机器可读快照
$BIN --diff before.json after.json               # 两份快照按 kind/source 聚合 diff
$BIN --events --trace -- /bin/true --help        # 追踪程序的 VMA syscall 事件流
$BIN --snapshot --trace ./build/mmap_leak_demo 1048576 100 4   # trace 后重建最终快照
$BIN --pid $$ --reconcile                         # 观测快照 vs /proc/maps 真值对账

# Layer 2: 页级驻留
$BIN --pid $$ --residency                         # mincore 自进程精确 / 跨进程 smaps 近似

# Layer 3: 页故障 (自进程安全 demo)
$BIN --uffd-demo --uffd-mode missing --uffd-length 12582912    # 首次访问缺页
$BIN --uffd-demo --uffd-mode wp --uffd-length 12582912         # 写保护页被写入

# Layer 4: 硬件性能
$BIN --pid $$ --perf-sample --perf-event dtlb-miss --duration-ms 5000
$BIN --pid $$ --perf-sample --perf-event cpu-clock --duration-ms 1000   # 软件事件,验证采样链路

# Layer 5: 容器压力
$BIN --cgroup self --psi --oom-risk

# 进阶页级探针 (需 --range, 支持 K/M/G 后缀)
$BIN --pid $$ --pages --range 0x7f4c00000000+128M     # pagemap: present/swapped/soft-dirty
$BIN --pid $$ --page-flags --range 0x7f4c00000000+128M # kpageflags: anon/THP/LRU/dirty
$BIN --pid $$ --numa --range 0x7f4c00000000+128M      # move_pages: 页所在 NUMA node
$BIN --pid $$ --clear-soft-dirty                       # 写 clear_refs 建立 soft-dirty 基线
$BIN --pid $$ --limits                                 # prlimit: RLIMIT_AS/STACK/...

# 趋势与联合分析
$BIN --pid $$ --growth-check 3 --interval-ms 1000     # 多采样线性趋势 (斜率 + R²)
$BIN --pid $$ --insights --residency --limits --cgroup self   # 跨层诊断建议
```

通用修饰参数：`--json`（机器可读输出，每个 region 带 `provenance` 来源标记）、`--with-smaps`（补 RSS/PSS/Private Dirty）、`--probe-memory`（`process_vm_readv` 抽样验证可读性/ELF）、`--watch`（周期刷新）。完整参数见 `mem-map-viewer --help`。

`--trace` 用法提示：被追踪程序自己需要 `--xxx` 参数时，用 `--trace -- <program> --xxx` 显式分隔，并把本工具的 `--events`/`--snapshot`/`--json` 放在 `--trace` 前面。

---

## 代码架构

### 目录结构

```
mem-map-viewer/
├── CMakeLists.txt                  # 构建定义: core 静态库 + 主程序 + 各 demo + CTest 用例;
│                                   #   mmv_warnings interface target 固化严格警告标志
├── README.md                       # 本文档
│
├── include/                        # 对外公共头 (库的 API 边界, 被 src/ 和外部消费者包含)
│   ├── mem_map_viewer.hpp          # 数据模型契约: 全部公共类型 (Region/MapEvent/Snapshot/
│   │                               #   各层 Report) + 全部公共函数声明; 所有模块围绕它工作
│   └── unique_fd.hpp               # RAII 文件描述符封装 (move-only, 析构自动 close, 异常安全)
│
├── src/                            # 全部实现 (按公共层 + Layer 1 + Layer 2-5 划分)
│   │
│   │   # ── 公共契约 / 工具 ──────────────────────────────────────────
│   ├── internal.hpp                # 模块间共享的内部声明: RegionIndex 区间索引、解析/格式化 helper
│   ├── util.cpp                    # 公共实现: 地址格式化、region 分类、RegionIndex (O(log n) 查找)
│   ├── main.cpp                    # 入口: CLI 解析、模式分发、参数互斥校验
│   ├── output.cpp                  # 渲染层: 全部表格 + JSON 输出 (只渲染, 不采集)
│   ├── json_parse.cpp              # 自实现 JSON 快照解析 (供 --diff 读回快照, 零第三方依赖)
│   │
│   │   # ── Layer 1: VMA 结构 ────────────────────────────────────────
│   ├── proc_seed.cpp               # 解析 /proc/<pid>/maps 与可选 smaps; attach/trace 基线 seed
│   ├── tracer.cpp                  # ptrace 追踪: fork+TRACEME, 优先 seccomp-BPF 过滤 +
│   │                               #   GET_SYSCALL_INFO, 回退 PTRACE_SYSCALL/GETREGS
│   ├── vma_model.hpp / vma_model.cpp  # 纯逻辑 VMA 模型: 事件重建快照, 区间 split/merge/remap
│   ├── fd_resolver.cpp             # 文件映射经 pidfd_getfd + fstat 解析 inode/dev/path
│   ├── diff.cpp                    # 两份快照按 region kind/source 聚合 diff
│   ├── growth_detector.cpp         # 多采样趋势判定: 单调性 + 最小二乘斜率/R² + 增长分桶
│   ├── reconcile.cpp               # 观测快照 vs /proc/maps 真值对账 (预留内核真值 provider 接口)
│   │
│   │   # ── Layer 2-5 + 进阶页级探针 ─────────────────────────────────
│   ├── residency.cpp               # Layer 2: mincore 自进程驻留 / 跨进程 smaps 近似
│   ├── uffd_tracer.cpp             # Layer 3: userfaultfd 捕获 missing/WP 页故障 (后台线程 + 放行)
│   ├── perf_sampler.cpp            # Layer 4: perf_event_open + ring buffer 采样, 经 RegionIndex 归因
│   ├── cgroup_observer.cpp         # Layer 5: 读 cgroup v2 memory.*/pressure, 算 OOM 风险分
│   ├── pagemap.cpp                 # 进阶: /proc/<pid>/pagemap present/swapped/soft-dirty/PFN
│   ├── page_flags.cpp              # 进阶: 经 PFN 读 /proc/kpageflags (anon/THP/LRU/dirty/slab)
│   ├── numa.cpp                    # 进阶: move_pages 查页所在 NUMA node
│   ├── clear_refs.cpp              # 进阶: 写 /proc/<pid>/clear_refs 建立 soft-dirty 基线
│   ├── limits.cpp                  # 进阶: prlimit 读 RLIMIT_AS/STACK/... 作为诊断上下文
│   └── correlate.cpp               # 纯逻辑跨层联合分析: 驻留浪费/访问热点/cgroup 压力 → insight
│
├── demos/                          # 可复现的内存行为样本程序 (制造特定行为供各层观测验证)
│   ├── mmap_leak.cpp               # 持续匿名 mmap 并触页不回收 → 验证 Layer 1 增长归因
│   ├── mprotect_flip.cpp           # 反复切换 VMA 权限 → 验证 Layer 1 mprotect 事件
│   ├── file_mapping.cpp            # 创建文件映射 → 验证 Layer 1 fd/inode/path 来源解析
│   ├── thread_stack_growth.cpp     # 创建多线程 → 验证 Layer 1 线程栈/匿名映射变化
│   ├── lazy_touch.cpp              # 映射大块匿名内存只触少量页 → 验证 Layer 2 低驻留率
│   ├── tlb_thrash.cpp              # 按页跨度伪随机访问大映射 → 验证 Layer 4 dTLB/cache miss
│   └── cgroup_pressure.cpp         # 按上限分批分配并触页 → 验证 Layer 5 cgroup/PSI
│
└── tests/
    └── smoke.cpp                   # CTest 冒烟测试: 用裸 assert 验证 vma_model/RegionIndex/
                                    #   JSON 往返等纯逻辑, 不引第三方测试框架
```

> 编译产物默认输出到 `build/`（被仓库 `.gitignore` 忽略），不纳入源码树。


### 设计原则

整个项目贯穿一条原则：**采集与渲染分离、纯逻辑可单测**。

- 每个采集模块只负责「问内核拿数据」，填进 `mem_map_viewer.hpp` 定义的结构体；
- `output` 只负责把结构体渲染成表格或 JSON，不碰采集；
- `vma_model`、`correlate`、`diff` 是纯逻辑，输入结构体输出结构体，不做 I/O，便于测试和对账。

### 模块职责

公共契约层：

| 文件 | 职责 |
| --- | --- |
| `include/mem_map_viewer.hpp` | 定义全部公共类型（`Region`/`MapEvent`/`Snapshot`/各 Report）和 API。所有模块围绕这些结构工作 |
| `include/unique_fd.hpp` | RAII fd，move-only，异常路径自动 close |
| `src/internal.hpp` | 模块间共享的内部工具（`RegionIndex` 区间索引、解析/格式化 helper） |
| `src/util.cpp` | 公共实现：地址格式化、region 分类、`RegionIndex`（有序区间 O(log n) 查找） |

Layer 1（VMA 结构）：

| 文件 | 职责 |
| --- | --- |
| `src/proc_seed.cpp` | 解析 `/proc/<pid>/maps`、可选 `smaps`；作为 attach/trace 的基线 seed 和对账真值 |
| `src/tracer.cpp` | `fork + PTRACE_TRACEME` 追踪；优先装 **seccomp-BPF** 只让 VMA 相关 syscall 触发 `PTRACE_EVENT_SECCOMP`（不可用则回退全量 `PTRACE_SYSCALL`）；解码优先 `PTRACE_GET_SYSCALL_INFO`，老内核回退 `PTRACE_GETREGS` |
| `src/vma_model.cpp` | 纯逻辑 VMA 模型：由事件重建快照，处理 map/unmap/protect/remap 的区间 split/merge，mremap 跨多区平移 |
| `src/fd_resolver.cpp` | 文件映射经 `/proc/<pid>/fd` + `pidfd_getfd` + `fstat` 解析 inode/dev/path |
| `src/diff.cpp` | 按 region kind/source 聚合两份快照的差异 |
| `src/growth_detector.cpp` | 连续多采样判趋势：单调性 + 最小二乘斜率/R² + 增长分桶 |
| `src/reconcile.cpp` | 用户态观测快照 vs `/proc/maps` 真值对账（为接内核侧真值 provider 预留接口） |

Layer 2-5 + 进阶探针：

| 文件 | 职责 |
| --- | --- |
| `src/residency.cpp` | `mincore` 自进程页级驻留；跨进程退化为 `smaps` RSS 近似并标记 |
| `src/uffd_tracer.cpp` | `userfaultfd` 注册自进程匿名映射，后台线程捕获 missing/WP 页故障并放行（eventfd 唤醒、EAGAIN 重试） |
| `src/perf_sampler.cpp` | `perf_event_open` + mmap ring buffer 读样本，经 `RegionIndex` 归因到 VMA，统计丢样 |
| `src/cgroup_observer.cpp` | 读 cgroup v2 `memory.current/max/stat/events/pressure`，算 OOM 风险分 |
| `src/pagemap.cpp` | 读 `/proc/<pid>/pagemap`：present/swapped/soft-dirty/exclusive/PFN 可见性 |
| `src/page_flags.cpp` | 经 pagemap PFN 读 `/proc/kpageflags`：anon/THP/LRU/dirty/slab（PFN 隐藏时优雅降级） |
| `src/numa.cpp` | `move_pages` 查页所在 NUMA node，保留 per-page 错误状态 |
| `src/clear_refs.cpp` | 写 `/proc/<pid>/clear_refs` 清 soft-dirty 位，建立新观测基线 |
| `src/limits.cpp` | `prlimit` 读资源限制，把 RLIMIT 纳入诊断上下文 |
| `src/correlate.cpp` | 纯逻辑跨层联合分析：低驻留浪费、访问热点、cgroup 压力、limit 逼近 → insight |
| `src/output.cpp` | 全部表格 + JSON 渲染 |
| `src/main.cpp` | CLI 解析、模式分发、参数互斥校验 |

### 关键数据模型

- **`Region`**：一段 VMA。`[begin, end)` 半开区间、`Perms`、`RegionKind`、`MappingSource`（fd/inode/dev/path/deleted）、RSS/PSS、`provenance`。
- **`provenance`**：标记该 region 的来源 —— `seed`（`/proc/maps` 基线）、`event`（ptrace 事件流更新）、`inferred`（由 brk 等推断）。让输出自带可信度标签。
- **`MapEvent`**：一次 VMA 相关 syscall 的 entry+exit 合并视图（类型、参数、返回值、成功标志）。
- **`Snapshot`**：某时刻的全部 `Region`，按 `begin` 升序。
- 各层独立 Report 结构（`ResidencyReport`/`PerfSampleReport`/`CgroupMemoryHealth`/`PageMapReport`/...），渲染层据此输出。

---

## 技术栈

- **语言**：C++17（`std::optional`、结构化绑定、`if constexpr` 等）
- **构建**：CMake 3.20+，CTest 驱动冒烟与端到端用例；`mmv_warnings` interface target 固化 `-Wall -Wextra -Wshadow -Wconversion -Wsign-conversion`
- **编译器**：GCC / Clang（C++17）
- **零第三方依赖**：仅用标准库 + Linux 系统调用，JSON 输出/解析自实现，测试用裸 `assert` + CTest，不引入测试框架

涉及的 Linux 内核接口（项目的核心学习价值所在）：

| 类别 | 接口 |
| --- | --- |
| 进程追踪 | `ptrace`（`PTRACE_SYSCALL` / `PTRACE_GET_SYSCALL_INFO` / `PTRACE_SETOPTIONS`）、`seccomp` cBPF 过滤、`waitpid` |
| fd / 内核对象 | `pidfd_open`、`pidfd_getfd`、`fstat`、`process_vm_readv` |
| 页级 | `mincore`、`userfaultfd`（`UFFDIO_*` ioctl）、`/proc/pid/pagemap`、`/proc/kpageflags`、`/proc/pid/clear_refs`、`move_pages` |
| 性能 | `perf_event_open` + mmap ring buffer（`PERF_TYPE_HW_CACHE` dTLB/cache miss、`PERF_RECORD_SAMPLE`/`PERF_RECORD_LOST`） |
| 资源 / 容器 | `prlimit`、cgroup v2 `memory.*`、PSI `memory.pressure` |
| /proc 解析 | `/proc/pid/maps`、`/proc/pid/smaps`、`/proc/pid/fd` |

C++ 工程实践：RAII（`UniqueFd`、mmap 守卫）封装内核资源、move 语义、纯逻辑模块与 I/O 分离便于单测、整数溢出与短读/权限失败的显式处理。

---

## Demos

`demos/` 下是一组制造特定内存行为的样本程序，用于验证各层观测能力：

```bash
# Layer 1: 匿名 mmap 泄漏
./build/mmap_leak_demo &
./build/mem-map-viewer --pid $! --summary --with-smaps; kill $!
./build/mem-map-viewer --events --trace ./build/mmap_leak_demo 1048576 100 4

# Layer 1: 权限切换 / 文件映射 / 线程栈
./build/mem-map-viewer --trace ./build/mprotect_flip_demo 100 6 --events
./build/mem-map-viewer --trace ./build/file_mapping_demo /tmp/mmv-file.bin 1 --events
./build/mem-map-viewer --trace ./build/thread_stack_growth_demo 8 262144 2 --events

# Layer 2: 大映射低驻留
./build/lazy_touch_demo 268435456 1048576 &
./build/mem-map-viewer --pid $! --residency --with-smaps; kill $!

# Layer 4: TLB 抖动
./build/tlb_thrash_demo 536870912 &
./build/mem-map-viewer --pid $! --perf-sample --perf-event dtlb-miss --duration-ms 5000; kill $!

# Layer 5: cgroup 压力
./build/cgroup_pressure_demo 134217728 8388608 &
./build/mem-map-viewer --cgroup self --psi --oom-risk; kill $!
```

| demo | 制造的行为 | 验证的层 |
| --- | --- | --- |
| `mmap_leak_demo` | 持续匿名 mmap 并触页，不回收 | Layer 1 增长归因 |
| `mprotect_flip_demo` | 反复切换 VMA 权限 | Layer 1 mprotect 事件 |
| `file_mapping_demo` | 创建文件映射 | Layer 1 fd/inode/path 来源解析 |
| `thread_stack_growth_demo` | 创建多线程 | Layer 1 线程栈/匿名映射变化 |
| `lazy_touch_demo` | 映射大块匿名内存但只触少量页 | Layer 2 驻留率远低于映射大小 |
| `tlb_thrash_demo` | 按页跨度伪随机访问大映射 | Layer 4 dTLB/cache miss 采样目标 |
| `cgroup_pressure_demo` | 按上限分批分配并触页 | Layer 5 cgroup memory.current / PSI |

---

## 使用场景与实战

下面按「问题 → 编译复现 → 看什么」组织，每个场景对应一个 demo。先约定：

```bash
BIN=./build/mem-map-viewer
DEMO=./build              # demo 可执行与主程序同目录
```

### 场景 1：服务内存上涨，分不清增长来自哪里

**问题**：C++ 服务 VIRT/RSS 长期增长，`top` 只告诉你总量在涨，分不清是 heap、匿名 mmap、文件映射还是线程栈。

**复现**：`mmap_leak_demo` 持续匿名 mmap 并触页、从不回收。

```bash
cmake --build build --target mmap_leak_demo
$DEMO/mmap_leak_demo &
pid=$!
$BIN --pid $pid --summary --with-smaps     # 按 kind/source 聚合，看哪类在涨
$BIN --pid $pid --growth-check 3 --interval-ms 1000   # 多采样判趋势
kill $pid
```

**看什么**：`--summary` 把 VMA 按 `kind:source` 聚合，`anonymous:[anon]` 那一行的 SIZE/RSS 持续居高即增长来源；`--growth-check` 输出 `monotonic_size`、线性回归斜率和增长分桶，区分「持续单调泄漏」与「抖动负载」。

---

### 场景 2：mmap 泄漏，哪些映射没被回收

**问题**：VIRT 很大、RSS 也涨，怀疑某处 `mmap` 后没 `munmap`。

**复现**：用 `--trace` 直接追踪 demo 的 VMA syscall 事件流。

```bash
$BIN --events --trace $DEMO/mmap_leak_demo 1048576 100 4
```

**看什么**：事件流里每个 `mmap` 都带返回地址和大小，数 `mmap` 与 `munmap` 是否配对——只增不减的匿名映射就是泄漏。trace 模式能把「谁、何时、映射多大」全部落到事件级，这是 `pmap` 静态快照给不出的。

---

### 场景 3：过度预分配 —— 映射很大但根本没用

**问题**：进程映射了一大块内存，但实际驻留（RSS）很低，白占地址空间。

**复现**：`lazy_touch_demo` 映射 256MB 匿名内存但只触碰少量页。

```bash
cmake --build build --target lazy_touch_demo
$DEMO/lazy_touch_demo 268435456 1048576 &
pid=$!
$BIN --pid $pid --residency --with-smaps
kill $pid
```

**看什么**：`--residency` 输出每段 VMA 的 `Resident%`。lazy 映射会显示驻留率极低（如 `0.2%`），直接量化「映射了 256M、实际只用了 1M」。自进程用 `mincore` 精确，跨进程退化为 smaps 近似并标记。

---

### 场景 4：JIT / 权限切换 —— 哪段地址被改了权限

**问题**：出现 rwx 段或频繁 mprotect，怀疑 JIT 或加载器行为异常。

**复现**：`mprotect_flip_demo` 反复切换一段 VMA 的权限。

```bash
cmake --build build --target mprotect_flip_demo
$BIN --trace $DEMO/mprotect_flip_demo 100 6 --events
```

**看什么**：事件流里的 `mprotect` 事件带 `addr/len/prot`，能看到某段地址从 `rw-` 改成 `r-x` 或 `---` 的完整过程和时刻——快照工具只能看到最终权限，看不到「什么时候被谁改的」。

---

### 场景 5：内存访问慢 —— 哪段内存 TLB/cache miss 最多

**问题**：RSS 不高但访问吃力，怀疑访问模式差（跨步、局部性差、未用大页）。

**复现**：`tlb_thrash_demo` 按页跨度伪随机访问大映射，制造 TLB 抖动。

```bash
cmake --build build --target tlb_thrash_demo
$DEMO/tlb_thrash_demo 536870912 &
pid=$!
$BIN --pid $pid --perf-sample --perf-event dtlb-miss --duration-ms 5000
$BIN --pid $pid --perf-sample --perf-event cpu-clock --duration-ms 1000   # PMU 受限时验证链路
kill $pid
```

**看什么**：perf 把 dTLB miss 采样按 VMA 聚合，thrash 数组所在区域应占多数采样，提示考虑大页或改善局部性。注意 `lost_samples`——非 0 说明 ring buffer 丢样、结果偏样本窗口尾部。云主机隐藏硬件 PMU 时用 `cpu-clock` 软件事件验证采样链路通不通。

---

### 场景 6：写热点分析 —— 哪些页真正被写过

**问题**：想知道一段内存里实际被写过的是哪些页（不是被读、不是只映射）。

**复现**：先清 soft-dirty 基线，跑一段 workload，再查 pagemap。

```bash
$BIN --pid $pid --clear-soft-dirty                          # 1. 清零观测基线
# … 让目标进程运行一段 workload …
$BIN --pid $pid --pages --range 0x7f4c00000000+128M         # 2. 统计 soft-dirty 页
```

**看什么**：`--pages` 输出指定范围内 present/swapped/**soft_dirty**/exclusive 页数量。soft_dirty 计数就是「自上次 clear 以来被写过的页数」。`pfn_visible=false` 时 PFN 被内核隐藏，但 soft-dirty 等标志仍可用。

---

### 场景 7：页类型与 NUMA 分布

**问题**：想区分一段内存是匿名页、THP 大页、文件页，或确认页落在哪个 NUMA node。

**复现**：对任意范围查页标志和 NUMA：

```bash
$BIN --pid $pid --page-flags --range 0x7f4c00000000+128M    # anon/THP/LRU/dirty/slab
$BIN --pid $pid --numa --range 0x7f4c00000000+128M          # 页所在 NUMA node
```

**看什么**：`--page-flags` 经 pagemap PFN 关联 `/proc/kpageflags`，聚合内核页标志（区分 THP、匿名、LRU 状态）；`--numa` 用 `move_pages` 报告页所在 node，并保留 `-ENOENT` 等 per-page 状态以区分「未驻留」和「权限/地址问题」。两者都需 `--range` 且受 PFN 可见性/权限限制。

---

### 场景 8：容器 OOM 预警

**问题**：pod 内存接近 limit，想在 OOM 前拿到压力信号。

**复现**：`cgroup_pressure_demo` 在受限场景下分批分配逼近上限。

```bash
cmake --build build --target cgroup_pressure_demo
$DEMO/cgroup_pressure_demo 134217728 8388608 &
$BIN --cgroup self --psi --oom-risk
```

**看什么**：`--psi` 输出 `memory.pressure` 的 some/full avg10/avg60；`--oom-risk` 给启发式风险分（综合用量比、full-stall、OOM 历史）。`full.avg10` 上升 + 用量逼近 limit 即 OOM 风险信号。要求 cgroup v2。

---

### 场景 9：事件流真值对账（理解观测边界）

**问题**：ptrace 事件流是增量真相，想知道它和内核真值差了哪些 region。

**复现**：

```bash
$BIN --pid $$ --reconcile
```

**看什么**：`--reconcile` 把当前观测快照和 `/proc/maps` 真值做区间对账，输出 `missing`（真值有、观测漏）、`extra`（观测有、真值无）、`metadata`（权限/类型不一致）。这是理解「用户态观测局限」的工具，也是后续接内核侧真值 provider 的接口落点。

---

### 场景 10：跨层联合诊断

**问题**：不想逐层手动看，想要一句话结论。

**复现**：

```bash
$BIN --pid $pid --insights --residency --limits --cgroup self
```

**看什么**：`--insights` 把 residency、perf、cgroup、limits 信号汇总成可读建议，例如「anon 映射 512M 仅驻留 7.4%，建议缩小预留」「VMA 总量接近 RLIMIT_AS」「cgroup full-pressure 升高，OOM 风险 0.71」。

---

## 权限与边界

- **架构**：syscall 解码主目标是 x86_64 Linux；其他架构需适配 syscall ABI。
- **ptrace（Layer 1）**：`--trace` 需 ptrace 权限，容器/生产可能受 Yama `ptrace_scope`、seccomp 策略限制。事件流是**增量真相**，`/proc/maps` 是**基线真相**——trace/attach 开始前已存在的映射、内核内部建立的 VMA 必须靠 seed 对齐（用 `--reconcile` 校验）。
- **mincore（Layer 2）**：只能精确查当前进程地址空间；`--pid <他进程> --residency` 会退化为 `smaps` RSS 估算并在输出标记为 approximation。
- **userfaultfd（Layer 3）**：受 `/proc/sys/vm/unprivileged_userfaultfd`、内核版本、容器策略影响。CLI 仅提供**自进程安全 demo**，避免监控外部进程时误挂住目标线程。
- **perf（Layer 4）**：硬件事件受 `/proc/sys/kernel/perf_event_paranoid`、容器 seccomp、虚拟化 PMU 支持影响；失败时输出明确降级原因。`cpu-clock` 走软件事件，适合在云主机隐藏 PMU 时验证采样链路。perf 输出含 `lost_samples` 用于判断 ring buffer 是否丢样。
- **cgroup（Layer 5）**：要求 cgroup v2；`memory.max=max`（无上限）时 OOM 风险分为 0。
- **pagemap / page-flags / numa**：必须显式 `--range`，单次最多扫描 1048576 页；新内核或低权限环境对非特权用户隐藏 PFN，此时 `pfn_visible=false`，但 present/swapped/soft-dirty 等标志仍可用。`move_pages` 受权限和内核策略限制，不足时结构化输出 unavailable。
- **clear-soft-dirty**：改变目标进程的 soft-dirty 观测位（不改业务内存内容），但会影响同时段其他观测者对 soft-dirty 的判断。
- **`--with-smaps` / `--probe-memory`**：成本高于单纯 maps，不适合高频 watch。

---

## 面试介绍

> 开发 **mem-map-viewer**：一个 Linux 分层进程内存观测工具集。
> VMA 结构层用 `ptrace(PTRACE_SYSCALL)` 追踪 mmap/munmap/mprotect/brk/mremap 重建地址空间事件流，并用 **seccomp-BPF 过滤**只让 VMA 相关 syscall 陷入、`PTRACE_GET_SYSCALL_INFO` 解码以降低 ptrace 开销；页级驻留层用 `mincore` 给出每段 VMA 的物理驻留率；页故障层用 `userfaultfd`（MISSING/WP 双模式）实时捕获页首次访问/写的时刻与读写类型；硬件性能层用 `perf_event_open` + mmap ring buffer 采样 dTLB/cache miss 并经有序区间索引归因到 VMA；容器压力层读 cgroup v2 `memory.*` 与 PSI 给出 OOM 风险评分。另有 pagemap/kpageflags/move_pages/clear_refs 等页级探针，以及用户态观测 vs `/proc/maps` 真值对账和跨层联合诊断。全程零第三方依赖、RAII 管理内核资源、采集与渲染分离、纯逻辑模块单测覆盖。

精简版：

> C++ Linux 分层内存观测工具：ptrace+seccomp 追踪 VMA 事件流、mincore 驻留分析、userfaultfd 页故障、perf TLB/cache miss 归因、cgroup/PSI 压力评估，支持快照 diff、趋势判定与跨层联合诊断。

技能关键词：

> C++17 · Linux · ptrace · seccomp-BPF · userfaultfd · mincore · perf_event_open · PMU · cgroup v2 · PSI · pagemap · move_pages · pidfd · VMA · RAII · CMake

---

## 许可说明

知识星球：“奔跑中cpp / c++” 所有，

阿甘微信：LLqueww

商业使用前请联系我方授权 一旦发现侵权行为，将依法追究法律责任

（对于公司法律事务已有对接律师，敬请告知）

