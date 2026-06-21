#include "decoder_internal.hpp"
#include "tracer_internal.hpp"

#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

namespace mini_strace {
namespace detail {
namespace {

enum class SyscallInfoKind {
    None,
    Entry,
    Exit,
    Seccomp,
};

struct SyscallInfoSnapshot {
    SyscallInfoKind kind = SyscallInfoKind::None;
    std::uint64_t nr = 0;
    std::array<std::uint64_t, 6> args{};
    std::int64_t rval = 0;
    bool is_error = false;
    std::uint32_t seccomp_ret_data = 0;
};

long ptrace_checked(enum __ptrace_request request, pid_t pid, void* addr, void* data,
                    const std::string& what) {
    errno = 0;
    const long rc = ::ptrace(request, pid, addr, data);
    if (rc == -1 && errno != 0) {
        throw syscall_error(what);
    }
    return rc;
}

long ptrace_no_throw(enum __ptrace_request request, pid_t pid, void* addr, void* data) {
    errno = 0;
    return ::ptrace(request, pid, addr, data);
}

std::array<std::uint64_t, 6> syscall_args_from_regs(const user_regs_struct& regs) {
    return {
        static_cast<std::uint64_t>(regs.rdi), static_cast<std::uint64_t>(regs.rsi),
        static_cast<std::uint64_t>(regs.rdx), static_cast<std::uint64_t>(regs.r10),
        static_cast<std::uint64_t>(regs.r8),  static_cast<std::uint64_t>(regs.r9),
    };
}

bool read_syscall_info(pid_t tid, SyscallInfoSnapshot& snapshot) {
#ifdef PTRACE_GET_SYSCALL_INFO
    __ptrace_syscall_info info{};
    errno = 0;
    const long rc =
        ::ptrace(PTRACE_GET_SYSCALL_INFO, tid, reinterpret_cast<void*>(sizeof(info)), &info);
    if (rc < 0) {
        return false;
    }
    switch (info.op) {
        case PTRACE_SYSCALL_INFO_ENTRY:
            snapshot.kind = SyscallInfoKind::Entry;
            snapshot.nr = info.entry.nr;
            for (std::size_t i = 0; i < snapshot.args.size(); ++i) {
                snapshot.args[i] = info.entry.args[i];
            }
            return true;
        case PTRACE_SYSCALL_INFO_EXIT:
            snapshot.kind = SyscallInfoKind::Exit;
            snapshot.rval = info.exit.rval;
            snapshot.is_error = info.exit.is_error != 0;
            return true;
        case PTRACE_SYSCALL_INFO_SECCOMP:
            snapshot.kind = SyscallInfoKind::Seccomp;
            snapshot.nr = info.seccomp.nr;
            for (std::size_t i = 0; i < snapshot.args.size(); ++i) {
                snapshot.args[i] = info.seccomp.args[i];
            }
            snapshot.seccomp_ret_data = info.seccomp.ret_data;
            return true;
        default:
            snapshot.kind = SyscallInfoKind::None;
            return true;
    }
#else
    (void)tid;
    (void)snapshot;
    return false;
#endif
}

const char* kernel_restart_errno_name(int value) {
    switch (value) {
        case 512:
            return "ERESTARTSYS";
        case 513:
            return "ERESTARTNOINTR";
        case 514:
            return "ERESTARTNOHAND";
        case 516:
            return "ERESTART_RESTARTBLOCK";
        default:
            return nullptr;
    }
}

void populate_error_fields(SyscallEvent& event) {
    if (!event.is_error) {
        return;
    }
    event.errno_value = static_cast<int>(-event.raw_ret);
    if (const char* restart_name = kernel_restart_errno_name(event.errno_value)) {
        event.errno_name = restart_name;
        event.errno_message = "kernel restart pseudo-errno before signal delivery";
        event.interrupted = true;
        return;
    }
    event.errno_name = errno_name(event.errno_value);
    event.errno_message = format_errno_message(event.errno_value);
    event.interrupted = event.errno_name == "EINTR";
}

bool passes_filter(const TraceOptions& options, const SyscallEvent& event) {
    return options.filters.empty() || options.filters.find(event.name) != options.filters.end();
}

void emit_event(const TraceOptions& options, std::ostream& out, TraceSession& session,
                SyscallEvent& event) {
    decode_event_for_state(event, options);
    session.state.enrich_before(event);
    session.state.apply(event);
    maybe_dump_target_seccomp_filters(event.tid, options, out, session.task_tgids,
                                      session.seccomp_dump, session.sequence);
    if (!passes_filter(options, event)) {
        return;
    }
    decode_event(event, options);
    ++session.result.events;
    session.pipeline.mutate(event);
    session.pipeline.observe(event);
    if (options.json) {
        out << format_event_json(event) << '\n';
    } else {
        out << format_event_text(event, options.raw, options.show_state, options.follow_fork)
            << '\n';
    }
}

SyscallEvent make_entry_event(pid_t tid, const user_regs_struct& regs, TraceSession& session) {
    SyscallEvent event;
    const auto tgid = session.task_tgids.find(tid);
    event.pid = tgid == session.task_tgids.end() ? tid : tgid->second;
    event.tid = tid;
    event.sequence = ++session.sequence;
    event.nr = static_cast<std::uint64_t>(regs.orig_rax);
    event.name = syscall_name(event.nr);
    event.raw_args = syscall_args_from_regs(regs);
    event.enter_ns = now_ns();
    return event;
}

SyscallEvent make_entry_event(pid_t tid, const SyscallInfoSnapshot& info, TraceSession& session) {
    SyscallEvent event;
    const auto tgid = session.task_tgids.find(tid);
    event.pid = tgid == session.task_tgids.end() ? tid : tgid->second;
    event.tid = tid;
    event.sequence = ++session.sequence;
    event.nr = info.nr;
    event.name = syscall_name(event.nr);
    event.raw_args = info.args;
    event.enter_ns = now_ns();
    if (info.kind == SyscallInfoKind::Seccomp) {
        SeccompContext context;
        context.ptrace_event = true;
        context.action = "SECCOMP_RET_TRACE";
        context.ret_data = info.seccomp_ret_data;
        event.seccomp_context = context;
    }
    return event;
}

void begin_syscall_from_regs(pid_t tid, user_regs_struct& regs, const TraceOptions& options,
                             TraceSession& session) {
    auto event = make_entry_event(tid, regs, session);
    apply_entry_injection(tid, regs, event, options, session.injection_seen);
    predecode_entry_event(event, options);
    auto& thread = session.threads[tid];
    thread.pending.active = true;
    thread.pending.event = std::move(event);
}

void begin_syscall_from_info(pid_t tid, const SyscallInfoSnapshot& info,
                             const TraceOptions& options, TraceSession& session) {
    auto event = make_entry_event(tid, info, session);
    if (!options.injections.empty()) {
        user_regs_struct regs{};
        ptrace_checked(PTRACE_GETREGS, tid, nullptr, &regs, "PTRACE_GETREGS inject entry");
        apply_entry_injection(tid, regs, event, options, session.injection_seen);
    }
    predecode_entry_event(event, options);
    auto& thread = session.threads[tid];
    thread.pending.active = true;
    thread.pending.event = std::move(event);
}

void complete_syscall_from_regs(pid_t tid, user_regs_struct& regs, const TraceOptions& options,
                                std::ostream& out, TraceSession& session) {
    auto& thread = session.threads[tid];
    if (!thread.pending.active) {
        return;
    }
    auto event = thread.pending.event;
    thread.pending.active = false;
    apply_exit_injection(tid, regs, event);
    event.exit_ns = now_ns();
    event.duration_ns = event.exit_ns >= event.enter_ns ? event.exit_ns - event.enter_ns : 0;
    event.raw_ret = event.injected ? -static_cast<std::int64_t>(event.injected_errno_value)
                                   : static_cast<std::int64_t>(regs.rax);
    event.is_error = event.raw_ret < 0 && event.raw_ret >= -4095;
    populate_error_fields(event);
    emit_event(options, out, session, event);
}

void complete_syscall_from_info(pid_t tid, const SyscallInfoSnapshot& info,
                                const TraceOptions& options, std::ostream& out,
                                TraceSession& session) {
    auto& thread = session.threads[tid];
    if (!thread.pending.active) {
        return;
    }
    auto event = thread.pending.event;
    thread.pending.active = false;
    if (event.injected) {
        user_regs_struct regs{};
        ptrace_checked(PTRACE_GETREGS, tid, nullptr, &regs, "PTRACE_GETREGS inject exit");
        apply_exit_injection(tid, regs, event);
    }
    event.exit_ns = now_ns();
    event.duration_ns = event.exit_ns >= event.enter_ns ? event.exit_ns - event.enter_ns : 0;
    event.raw_ret =
        event.injected ? -static_cast<std::int64_t>(event.injected_errno_value) : info.rval;
    event.is_error =
        event.injected || info.is_error || (event.raw_ret < 0 && event.raw_ret >= -4095);
    populate_error_fields(event);
    emit_event(options, out, session, event);
}

void handle_syscall_stop(pid_t tid, const TraceOptions& options, std::ostream& out,
                         TraceSession& session) {
#if !defined(__x86_64__)
    throw std::runtime_error("mini-strace currently supports only x86_64 Linux");
#else
    SyscallInfoSnapshot info;
    if (read_syscall_info(tid, info)) {
        if (info.kind == SyscallInfoKind::Entry) {
            begin_syscall_from_info(tid, info, options, session);
            return;
        }
        if (info.kind == SyscallInfoKind::Exit) {
            complete_syscall_from_info(tid, info, options, out, session);
            return;
        }
    }

    user_regs_struct regs{};
    ptrace_checked(PTRACE_GETREGS, tid, nullptr, &regs, "PTRACE_GETREGS");

    auto& thread = session.threads[tid];
    if (!thread.pending.active) {
        begin_syscall_from_regs(tid, regs, options, session);
        return;
    }

    complete_syscall_from_regs(tid, regs, options, out, session);
#endif
}

void handle_seccomp_stop(pid_t tid, const TraceOptions& options, TraceSession& session) {
#if !defined(__x86_64__)
    throw std::runtime_error("mini-strace currently supports only x86_64 Linux");
#else
    SyscallInfoSnapshot info;
    if (read_syscall_info(tid, info) && info.kind == SyscallInfoKind::Seccomp) {
        begin_syscall_from_info(tid, info, options, session);
        return;
    }

    user_regs_struct regs{};
    ptrace_checked(PTRACE_GETREGS, tid, nullptr, &regs, "PTRACE_GETREGS");
    begin_syscall_from_regs(tid, regs, options, session);
#endif
}

pid_t read_task_tgid(pid_t tid) {
    const std::filesystem::path status_path =
        std::filesystem::path("/proc") / std::to_string(tid) / "status";
    std::ifstream in(status_path);
    std::string key;
    while (in >> key) {
        if (key == "Tgid:") {
            long tgid = -1;
            in >> tgid;
            if (tgid > 0) {
                return static_cast<pid_t>(tgid);
            }
            return -1;
        }
        std::string ignored;
        std::getline(in, ignored);
    }
    return -1;
}

pid_t parent_tgid_for(pid_t tid, const TraceSession& session) {
    const auto it = session.task_tgids.find(tid);
    return it == session.task_tgids.end() ? tid : it->second;
}

pid_t tgid_for_ptrace_child(pid_t parent_tid, pid_t child_tid, unsigned event,
                            const TraceSession& session) {
    if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK) {
        return child_tid;
    }
    const pid_t proc_tgid = read_task_tgid(child_tid);
    if (proc_tgid > 0) {
        return proc_tgid;
    }
    return parent_tgid_for(parent_tid, session);
}

void handle_ptrace_event(pid_t tid, unsigned event, const TraceOptions& options,
                         TraceSession& session) {
    if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
        unsigned long message = 0;
        if (ptrace_no_throw(PTRACE_GETEVENTMSG, tid, nullptr, &message) == -1) {
            return;
        }
        const pid_t child = static_cast<pid_t>(message);
        if (child > 0 && options.follow_fork) {
            session.tasks.insert(child);
            session.threads.emplace(child, ThreadState{});
            session.task_tgids[child] = tgid_for_ptrace_child(tid, child, event, session);
            resume_tracee(child, options.seccomp_bpf ? ResumeMode::Continue : ResumeMode::Syscall,
                          0);
        }
    }
    if (event == PTRACE_EVENT_EXEC) {
        // Keep the pending execve entry. Linux reports PTRACE_EVENT_EXEC before
        // the matching syscall-exit stop, and clearing it here inverts every
        // later entry/exit pair into apparent ENOSYS failures.
        session.state.on_exec();
    }
}

void detach_remaining(const std::set<pid_t>& tasks) {
    for (pid_t tid : tasks) {
        ptrace_no_throw(PTRACE_DETACH, tid, nullptr, nullptr);
    }
}

}  // namespace

std::runtime_error syscall_error(const std::string& what) {
    return std::runtime_error(format_operation_error(what, errno));
}

void resume_tracee(pid_t tid, ResumeMode mode, int signal) {
    const auto request = mode == ResumeMode::Syscall ? PTRACE_SYSCALL : PTRACE_CONT;
    if (ptrace_no_throw(request, tid, nullptr,
                        reinterpret_cast<void*>(static_cast<std::uintptr_t>(signal))) == -1 &&
        errno != ESRCH) {
        throw syscall_error(mode == ResumeMode::Syscall ? "PTRACE_SYSCALL" : "PTRACE_CONT");
    }
}

TraceResult event_loop(const TraceOptions& options, std::ostream& out, std::ostream& err,
                       TraceSession& session) {
    while (!session.tasks.empty()) {
        if (options.max_events != 0 && session.result.events >= options.max_events) {
            detach_remaining(session.tasks);
            break;
        }

        int status = 0;
        const pid_t tid = ::waitpid(-1, &status, __WALL);
        if (tid < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ECHILD) {
                break;
            }
            throw syscall_error("waitpid");
        }

        if (WIFEXITED(status)) {
            emit_exit_event(options, out, session.task_tgids, session.sequence, session.result,
                            session.primary_pid, tid, WEXITSTATUS(status));
            if (tid == session.primary_pid) {
                session.result.exit_code = WEXITSTATUS(status);
            }
            session.tasks.erase(tid);
            session.threads.erase(tid);
            session.task_tgids.erase(tid);
            continue;
        }
        if (WIFSIGNALED(status)) {
            emit_signaled_event(options, out, session.task_tgids, session.sequence, session.result,
                                session.primary_pid, tid, WTERMSIG(status));
            if (tid == session.primary_pid) {
                session.result.signaled = true;
                session.result.term_signal = WTERMSIG(status);
                session.result.exit_code = 128 + session.result.term_signal;
            }
            session.tasks.erase(tid);
            session.threads.erase(tid);
            session.task_tgids.erase(tid);
            continue;
        }
        if (!WIFSTOPPED(status)) {
            continue;
        }

        const int sig = WSTOPSIG(status);
        const unsigned event = static_cast<unsigned>(status >> 16);
        try {
            if (sig == (SIGTRAP | 0x80)) {
                handle_syscall_stop(tid, options, out, session);
                resume_tracee(tid, options.seccomp_bpf ? ResumeMode::Continue : ResumeMode::Syscall,
                              0);
                continue;
            }
            if (sig == SIGTRAP && event == PTRACE_EVENT_SECCOMP) {
                handle_seccomp_stop(tid, options, session);
                resume_tracee(tid, ResumeMode::Syscall, 0);
                continue;
            }
            if (sig == SIGTRAP && event != 0) {
                handle_ptrace_event(tid, event, options, session);
                resume_tracee(tid, options.seccomp_bpf ? ResumeMode::Continue : ResumeMode::Syscall,
                              0);
                continue;
            }
            const int deliver = sig == SIGSTOP || sig == SIGTRAP ? 0 : sig;
            emit_signal_event(options, out, session.task_tgids, session.sequence, session.result,
                              tid, sig, deliver != 0);
            resume_tracee(tid, options.seccomp_bpf ? ResumeMode::Continue : ResumeMode::Syscall,
                          deliver);
        } catch (const std::exception& ex) {
            err << "mini-strace: " << ex.what() << '\n';
            resume_tracee(tid, options.seccomp_bpf ? ResumeMode::Continue : ResumeMode::Syscall, 0);
        }
    }

    session.pipeline.finish(out);
    return session.result;
}

}  // namespace detail
}  // namespace mini_strace
