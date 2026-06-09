# cpp-sys-labs

> 一组用 C++ 实现的 Linux 系统编程小组件 —— 把 pidfd、ptrace、netlink、io_uring、
> eBPF、namespace 这些底层机制一个个吃透，既能真正用于排障，也能为简历攒下有含金量的技术栈。

## 这个仓库是干什么的

`cpp-sys-labs` 不是从零写一个完整操作系统，而是用一系列**可独立完成、可演示、可写进简历**的
C++ 小组件，系统性地理解 Linux/操作系统底层能力。核心理念：

- **走真实内核接口，不读 `/proc` 文本糊弄**：默认用 `pidfd`、`ptrace`、`netlink`、
  `ioctl`、`io_uring`、`eBPF` 等二进制/主动探测接口，`procfs` 只作兼容回退和校验基准。
- **每个组件都对标一个标准工具**（lsof / ss / strace / pmap …），用它做正确性校验——
  "自己写的和标准命令对不上，就说明哪里没理解透"。
- **每个组件都能讲出差异化**：不止"重写一个 lsof"，而要做标准命令做不到的事
  （趋势归因、关联分析、库化嵌入、领域化统计）。
- **工程化完整**：RAII、结构化输出（JSON）、可复现的事故 demo、回归测试、独立 CMake 工程。

一句话定位：

```
会 C++，懂 Linux，能排查底层问题，能写工程化系统工具。
```

每个子项目都是**完全独立的 CMake 工程**，在各自目录下 `cmake -B build` 即可单独构建，
互不依赖。

## 子项目

### fd-inspector — 进程 fd / socket 透视器（对标 `lsof` + `ss`）

[→ 进入 fd-inspector，查看完整文档与使用场景](fd-inspector/README.md)

用 `pidfd_open` + `pidfd_getfd` 把目标进程的文件描述符**复制**到本进程，再用普通 fd
系统调用直接审问内核对象；socket 详情走 `NETLINK_SOCK_DIAG` 二进制协议按 inode 反查。
它专注于 `lsof`/`ss` 单独做不到的事，并附带一个可选的 eBPF 泄漏追踪器把"周期采样推断"
升级为"事件级因果定位"。

亮点能力：

- **跨进程复制 fd**：`pidfd_getfd` + `fstat`/`fcntl`/`getsockopt`，触发真实 ptrace 权限检查。
- **手写 sock_diag 协议**：解析 inet_diag / unix_diag 的二进制 netlink，拿到 TCP 状态、
  RTT、拥塞窗口、重传、socket 内存——这些 `/proc/net/tcp` 都不提供。
- **趋势式 fd 泄漏检测**：多点采样 + 单调性判定 + 按类型/target 归因，并能关联
  socket 增长与 `CLOSE_WAIT` 判定连接泄漏。
- **容器感知**：`setns` 进目标进程的 network namespace 做 socket dump。
- **可选 eBPF 追踪器**：CO-RE + ringbuf + 用户态调用栈 + ELF 符号 + addr2line，
  把泄漏定位到打开它的那行代码。

适合排查：`Too many open files`、fd / 连接泄漏、`CLOSE_WAIT` 堆积、删除文件仍占磁盘、
epoll/eventfd 状态异常、容器内 socket 诊断等。详见
[fd-inspector/README.md](fd-inspector/README.md)。

## 规划与路线

本仓库按 OS 子系统系统性铺开（进程、内存、并发、I/O、文件系统、链接调试、容器隔离，
直至内核态），完整选型、分层路线、对标策略与权限/ABI 注意事项见：

- [操作系统规划.md](操作系统规划.md) — 整体方向、分层路线（观测 → 跟踪 → 造运行时 →
  组合隔离 → 进内核）、覆盖矩阵与推进顺序。
- [fd-inspector实现文档.md](fd-inspector实现文档.md) — fd-inspector 的详细实现指南。

> 当前已落地：**fd-inspector**。其余项目按规划文档逐步推进，每个都遵循"对标标准工具 +
> 一条差异化 + 可复现 demo + 回归测试"的同一套标准。
