#include "internal.hpp"
#include "unique_fd.hpp"
#include "vma_model.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <map>
#include <signal.h>
#include <stddef.h>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

namespace mmv {
namespace {

struct PendingSyscall {
    long nr = -1;
    std::array<uint64_t, 6> args{};
};

enum class SyscallStopKind {
    None,
    Entry,
    Exit,
};

struct SyscallStop {
    SyscallStopKind kind = SyscallStopKind::None;
    PendingSyscall pending;
    long retval = 0;
};

enum class TraceMode {
    SyscallStops,
    SeccompFilter,
};

bool is_vma_syscall(long nr) {
    return nr == __NR_mmap || nr == __NR_munmap || nr == __NR_mprotect || nr == __NR_brk ||
           nr == __NR_mremap || nr == __NR_execve || nr == __NR_execveat;
}

bool is_exec_syscall(long nr) {
    return nr == __NR_execve || nr == __NR_execveat;
}

std::string syscall_name(long nr) {
    switch (nr) {
        case __NR_mmap:
            return "mmap";
        case __NR_munmap:
            return "munmap";
        case __NR_mprotect:
            return "mprotect";
        case __NR_brk:
            return "brk";
        case __NR_mremap:
            return "mremap";
        case __NR_execve:
            return "execve";
        case __NR_execveat:
            return "execveat";
        default:
            return "unknown";
    }
}

Perms prot_to_perms(uint64_t prot, uint64_t flags = 0) {
    Perms perms;
    perms.read = (prot & PROT_READ) != 0;
    perms.write = (prot & PROT_WRITE) != 0;
    perms.exec = (prot & PROT_EXEC) != 0;
    perms.shared = (flags & MAP_SHARED) != 0;
    return perms;
}

bool syscall_succeeded(const PendingSyscall& pending, long retval) {
    if (pending.nr == __NR_brk) {
        const uint64_t requested = pending.args[0];
        return requested == 0 || (retval > 0 && static_cast<uint64_t>(retval) == requested);
    }
    return retval >= 0;
}

MapEvent event_from_syscall(pid_t pid, pid_t tid, const PendingSyscall& pending, long retval) {
    MapEvent event;
    event.pid = pid;
    event.tid = tid;
    event.timestamp_ns = detail::now_ns();
    event.syscall = syscall_name(pending.nr);
    event.result = retval;
    event.success = syscall_succeeded(pending, retval);

    switch (pending.nr) {
        case __NR_mmap:
            event.type = MapEventType::Mmap;
            event.address = event.success ? static_cast<uint64_t>(retval) : pending.args[0];
            event.length = pending.args[1];
            event.perms = prot_to_perms(pending.args[2], pending.args[3]);
            event.flags = pending.args[3];
            event.fd = static_cast<int>(pending.args[4]);
            event.offset = pending.args[5];
            if (event.success && (event.flags & MAP_ANONYMOUS) == 0 && event.fd >= 0) {
                event.source = resolve_mapping_fd(pid, event.fd, event.offset);
            }
            break;
        case __NR_munmap:
            event.type = MapEventType::Munmap;
            event.address = pending.args[0];
            event.length = pending.args[1];
            break;
        case __NR_mprotect:
            event.type = MapEventType::Mprotect;
            event.address = pending.args[0];
            event.length = pending.args[1];
            event.perms = prot_to_perms(pending.args[2]);
            break;
        case __NR_brk:
            event.type = MapEventType::Brk;
            event.address = pending.args[0];
            break;
        case __NR_mremap:
            event.type = MapEventType::Mremap;
            event.address = pending.args[0];
            event.length = pending.args[1];
            event.new_length = pending.args[2];
            event.flags = pending.args[3];
            event.new_address = event.success ? static_cast<uint64_t>(retval) : pending.args[4];
            break;
        case __NR_execve:
        case __NR_execveat:
            event.type = MapEventType::Exec;
            break;
        default:
            event.type = MapEventType::ProcSeed;
            break;
    }
    return event;
}

MapEvent exec_event_from_ptrace(pid_t pid, pid_t tid, const PendingSyscall* pending) {
    MapEvent event;
    event.type = MapEventType::Exec;
    event.pid = pid;
    event.tid = tid;
    event.timestamp_ns = detail::now_ns();
    event.success = true;
    event.result = 0;
    event.syscall = pending ? syscall_name(pending->nr) : "exec";
    return event;
}

PendingSyscall pending_from_regs(const user_regs_struct& regs) {
    PendingSyscall pending;
    pending.nr = static_cast<long>(regs.orig_rax);
    pending.args = {regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9};
    return pending;
}

PendingSyscall pending_from_info_entry(const __ptrace_syscall_info& info) {
    PendingSyscall pending;
    pending.nr = static_cast<long>(info.entry.nr);
    for (size_t i = 0; i < pending.args.size(); ++i) {
        pending.args[i] = info.entry.args[i];
    }
    return pending;
}

SyscallStop syscall_stop_from_regs(pid_t tid, bool entering) {
    SyscallStop stop;
    user_regs_struct regs{};
    if (::ptrace(PTRACE_GETREGS, tid, 0, &regs) != 0) {
        return stop;
    }
    if (entering) {
        stop.kind = SyscallStopKind::Entry;
        stop.pending = pending_from_regs(regs);
    } else {
        stop.kind = SyscallStopKind::Exit;
        stop.retval = static_cast<long>(regs.rax);
    }
    return stop;
}

SyscallStop read_syscall_stop(pid_t tid, bool entering) {
    __ptrace_syscall_info info{};
    if (::ptrace(PTRACE_GET_SYSCALL_INFO, tid, sizeof(info), &info) >= 0) {
        SyscallStop stop;
        if (info.op == PTRACE_SYSCALL_INFO_ENTRY || info.op == PTRACE_SYSCALL_INFO_SECCOMP) {
            stop.kind = SyscallStopKind::Entry;
            stop.pending = pending_from_info_entry(info);
            return stop;
        }
        if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
            stop.kind = SyscallStopKind::Exit;
            stop.retval = static_cast<long>(info.exit.rval);
            return stop;
        }
    }
    return syscall_stop_from_regs(tid, entering);
}

std::vector<char*> argv_for_child(const std::vector<std::string>& command) {
    std::vector<char*> argv;
    argv.reserve(command.size() + 1);
    for (const std::string& item : command) {
        argv.push_back(const_cast<char*>(item.c_str()));
    }
    argv.push_back(nullptr);
    return argv;
}

bool install_seccomp_trace_filter() noexcept {
    sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<unsigned int>(offsetof(seccomp_data, nr))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_munmap, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_brk, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mremap, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    sock_fprog program{};
    program.len = static_cast<unsigned short>(std::size(filter));
    program.filter = filter;
    return ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
           ::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0;
}

void write_setup_status(int fd, bool seccomp_enabled) noexcept {
    const char status = seccomp_enabled ? '1' : '0';
    ssize_t ignored = ::write(fd, &status, sizeof(status));
    (void)ignored;
}

bool read_setup_status(int fd) {
    char status = '0';
    ssize_t n = 0;
    do {
        n = ::read(fd, &status, sizeof(status));
    } while (n < 0 && errno == EINTR);
    return n == sizeof(status) && status == '1';
}

void resume_tracee(pid_t tid, TraceMode mode, int signal = 0, bool syscall_exit = false) {
    const auto request =
        mode == TraceMode::SyscallStops || syscall_exit ? PTRACE_SYSCALL : PTRACE_CONT;
    if (::ptrace(request, tid, 0, signal) != 0) {
        throw std::runtime_error("ptrace resume failed: " + std::string(std::strerror(errno)));
    }
}

void configure_tracee(pid_t pid, TraceMode mode) {
    long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE |
                   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
    if (mode == TraceMode::SeccompFilter) {
        options |= PTRACE_O_TRACESECCOMP;
    }
    if (::ptrace(PTRACE_SETOPTIONS, pid, 0, options) != 0) {
        throw std::runtime_error("PTRACE_SETOPTIONS failed: " + std::string(std::strerror(errno)));
    }
}

class TraceeGuard {
public:
    explicit TraceeGuard(pid_t pid) : pid_(pid) {}
    ~TraceeGuard() {
        if (pid_ <= 0 || dismissed_) {
            return;
        }
        ::kill(pid_, SIGKILL);
        int status = 0;
        while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
        }
    }

    TraceeGuard(const TraceeGuard&) = delete;
    TraceeGuard& operator=(const TraceeGuard&) = delete;

    void dismiss() { dismissed_ = true; }

private:
    pid_t pid_ = -1;
    bool dismissed_ = false;
};

}  // namespace

TraceResult trace_program(const std::vector<std::string>& command, const SnapshotOptions& options) {
    if (command.empty()) {
        throw std::invalid_argument("--trace requires a program");
    }

    int pipe_fds[2] = {-1, -1};
    if (::pipe2(pipe_fds, O_CLOEXEC) != 0) {
        throw std::runtime_error("pipe2 failed: " + std::string(std::strerror(errno)));
    }
    UniqueFd setup_read(pipe_fds[0]);
    UniqueFd setup_write(pipe_fds[1]);

    pid_t child = ::fork();
    if (child < 0) {
        throw std::runtime_error("fork failed: " + std::string(std::strerror(errno)));
    }
    if (child == 0) {
        setup_read.reset();
        bool seccomp_enabled = install_seccomp_trace_filter();
        write_setup_status(setup_write.get(), seccomp_enabled);
        setup_write.reset();
        if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) {
            _exit(127);
        }
        ::raise(SIGSTOP);
        std::vector<char*> argv = argv_for_child(command);
        ::execvp(argv[0], argv.data());
        _exit(127);
    }
    TraceeGuard guard(child);
    setup_write.reset();
    TraceMode mode =
        read_setup_status(setup_read.get()) ? TraceMode::SeccompFilter : TraceMode::SyscallStops;
    setup_read.reset();

    int status = 0;
    if (::waitpid(child, &status, 0) < 0) {
        throw std::runtime_error("waitpid failed: " + std::string(std::strerror(errno)));
    }
    configure_tracee(child, mode);

    Snapshot seed;
    try {
        seed = read_proc_snapshot(child, options);
    } catch (const std::exception&) {
        seed.pid = child;
        seed.timestamp_ns = detail::now_ns();
    }
    VmaModel model(seed);
    TraceResult result;
    result.pid = child;

    std::map<pid_t, bool> entering;
    std::map<pid_t, PendingSyscall> pending;
    entering[child] = true;

    resume_tracee(child, mode);

    auto reseed_after_exec = [&](pid_t tid, const PendingSyscall* pending_syscall) {
        MapEvent event = exec_event_from_ptrace(child, tid, pending_syscall);
        result.events.push_back(event);
        model.apply(event);
        try {
            model = VmaModel(read_proc_snapshot(child, options));
        } catch (const std::exception&) {
        }
    };

    while (true) {
        pid_t tid = ::waitpid(-1, &status, __WALL);
        if (tid < 0) {
            if (errno == ECHILD) {
                break;
            }
            throw std::runtime_error("waitpid trace loop failed: " +
                                     std::string(std::strerror(errno)));
        }

        if (WIFEXITED(status)) {
            if (tid == child) {
                result.exit_status = WEXITSTATUS(status);
            }
            entering.erase(tid);
            pending.erase(tid);
            if (tid == child) {
                break;
            }
            continue;
        }
        if (WIFSIGNALED(status)) {
            if (tid == child) {
                result.exit_status = 128 + WTERMSIG(status);
                break;
            }
            continue;
        }

        if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
            SyscallStop stop = read_syscall_stop(tid, entering[tid]);
            if (stop.kind == SyscallStopKind::Entry) {
                if (is_vma_syscall(stop.pending.nr)) {
                    pending[tid] = stop.pending;
                }
                entering[tid] = false;
            } else if (stop.kind == SyscallStopKind::Exit) {
                auto it = pending.find(tid);
                if (it != pending.end()) {
                    MapEvent event = event_from_syscall(child, tid, it->second, stop.retval);
                    result.events.push_back(event);
                    model.apply(event);
                    pending.erase(it);
                }
                entering[tid] = true;
            }
            resume_tracee(tid, mode);
            continue;
        }

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            unsigned long message = 0;
            int event = status >> 16;
            if (event == PTRACE_EVENT_SECCOMP) {
                SyscallStop stop = read_syscall_stop(tid, true);
                if (stop.kind == SyscallStopKind::Entry && is_vma_syscall(stop.pending.nr)) {
                    pending[tid] = stop.pending;
                    entering[tid] = false;
                    resume_tracee(tid, mode, 0, true);
                } else {
                    resume_tracee(tid, mode);
                }
                continue;
            }
            if (event == PTRACE_EVENT_EXEC) {
                auto it = pending.find(tid);
                const PendingSyscall* pending_syscall = nullptr;
                if (it != pending.end() && is_exec_syscall(it->second.nr)) {
                    pending_syscall = &it->second;
                }
                reseed_after_exec(tid, pending_syscall);
                pending.erase(tid);
                entering[tid] = true;
                resume_tracee(tid, mode);
                continue;
            }
            if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK ||
                event == PTRACE_EVENT_VFORK) {
                if (::ptrace(PTRACE_GETEVENTMSG, tid, 0, &message) == 0) {
                    entering[static_cast<pid_t>(message)] = true;
                }
            }
            resume_tracee(tid, mode);
            continue;
        }

        int signal = WIFSTOPPED(status) ? WSTOPSIG(status) : 0;
        resume_tracee(tid, mode, signal);
    }

    result.snapshot = model.snapshot();
    guard.dismiss();
    return result;
}

}  // namespace mmv
