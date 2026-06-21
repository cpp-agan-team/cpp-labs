#include "tracer_internal.hpp"

#include <csignal>
#include <cstdint>
#include <sstream>
#include <stddef.h>
#include <stdexcept>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace mini_strace {
namespace {

pid_t launch_tracee(const TraceOptions& options) {
    const auto& command = options.command;
    if (command.empty()) {
        throw std::runtime_error("missing command");
    }
    const pid_t child = ::fork();
    if (child < 0) {
        throw detail::syscall_error("fork");
    }
    if (child == 0) {
        if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
            _exit(127);
        }
        ::raise(SIGSTOP);
        if (options.seccomp_bpf && detail::install_seccomp_filter(options.filters) != 0) {
            _exit(126);
        }
        std::vector<char*> argv;
        argv.reserve(command.size() + 1);
        for (const auto& part : command) {
            argv.push_back(const_cast<char*>(part.c_str()));
        }
        argv.push_back(nullptr);
        ::execvp(argv[0], argv.data());
        _exit(127);
    }
    return child;
}

TraceResult run_trace_impl(const TraceOptions& options, std::ostream& out, std::ostream& err,
                           EventSink* sink) {
#if !defined(__x86_64__)
    throw std::runtime_error("mini-strace currently supports only x86_64 Linux");
#else
    detail::TraceSession session;
    detail::configure_event_pipeline(options, session.pipeline, sink);
    detail::maybe_emit_generated_seccomp_filter_dump(options, out, session.sequence);
    if (options.mode == TraceMode::Launch) {
        const pid_t child = launch_tracee(options);
        session.primary_pid = child;
        session.tasks.insert(child);
        session.threads.emplace(child, detail::ThreadState{});
        session.task_tgids[child] = child;

        int status = 0;
        if (::waitpid(child, &status, 0) < 0) {
            throw detail::syscall_error("waitpid initial child stop");
        }
        if (!WIFSTOPPED(status)) {
            throw std::runtime_error("tracee did not stop before exec");
        }
        detail::set_trace_options(child, true, options.follow_fork, options.seccomp_bpf);
        detail::resume_tracee(
            child, options.seccomp_bpf ? detail::ResumeMode::Continue : detail::ResumeMode::Syscall,
            0);
    } else {
        if (options.attach_pid <= 0) {
            throw std::runtime_error("invalid --pid value");
        }
        session.primary_pid = options.attach_pid;
        session.state.seed_from_proc(options.attach_pid);
        long options_mask = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC;
        if (options.follow_fork) {
            options_mask |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE;
        }
        const auto tids = detail::enumerate_tids(options.attach_pid);
        for (pid_t tid : tids) {
            detail::ptrace_attach_checked(
                PTRACE_SEIZE, options.attach_pid, tid,
                reinterpret_cast<void*>(static_cast<std::uintptr_t>(options_mask)), "PTRACE_SEIZE");
            detail::ptrace_attach_checked(PTRACE_INTERRUPT, options.attach_pid, tid, nullptr,
                                          "PTRACE_INTERRUPT");
            session.tasks.insert(tid);
            session.threads.emplace(tid, detail::ThreadState{});
            session.task_tgids[tid] = options.attach_pid;
        }
        std::size_t stopped = 0;
        while (stopped < tids.size()) {
            int status = 0;
            const pid_t tid = ::waitpid(-1, &status, __WALL);
            if (tid < 0) {
                throw detail::syscall_error("waitpid attach stop");
            }
            if (WIFSTOPPED(status)) {
                ++stopped;
                detail::maybe_dump_target_seccomp_filters(tid, options, out, session.task_tgids,
                                                          session.seccomp_dump, session.sequence);
                detail::resume_tracee(tid, detail::ResumeMode::Syscall, 0);
            }
        }
    }
    return detail::event_loop(options, out, err, session);
#endif
}

}  // namespace

TraceResult run_trace(const TraceOptions& options, std::ostream& out, std::ostream& err) {
    return run_trace_impl(options, out, err, nullptr);
}

TraceResult trace(const TraceOptions& options, EventSink& sink, std::ostream& err) {
    std::ostringstream discard;
    return run_trace_impl(options, discard, err, &sink);
}

}  // namespace mini_strace
