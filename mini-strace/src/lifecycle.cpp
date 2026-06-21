#include "internal.hpp"

#include <csignal>
#include <cstring>
#include <ostream>
#include <sys/types.h>

namespace mini_strace {
namespace detail {
namespace {

const char* signal_name(int signal) {
    switch (signal) {
        case SIGHUP:
            return "SIGHUP";
        case SIGINT:
            return "SIGINT";
        case SIGQUIT:
            return "SIGQUIT";
        case SIGILL:
            return "SIGILL";
        case SIGTRAP:
            return "SIGTRAP";
        case SIGABRT:
            return "SIGABRT";
        case SIGBUS:
            return "SIGBUS";
        case SIGFPE:
            return "SIGFPE";
        case SIGKILL:
            return "SIGKILL";
        case SIGUSR1:
            return "SIGUSR1";
        case SIGSEGV:
            return "SIGSEGV";
        case SIGUSR2:
            return "SIGUSR2";
        case SIGPIPE:
            return "SIGPIPE";
        case SIGALRM:
            return "SIGALRM";
        case SIGTERM:
            return "SIGTERM";
        case SIGCHLD:
            return "SIGCHLD";
        case SIGCONT:
            return "SIGCONT";
        case SIGSTOP:
            return "SIGSTOP";
        case SIGTSTP:
            return "SIGTSTP";
        case SIGTTIN:
            return "SIGTTIN";
        case SIGTTOU:
            return "SIGTTOU";
        default:
            return "SIGUNKNOWN";
    }
}

pid_t event_pid(const std::unordered_map<pid_t, pid_t>& task_tgids, pid_t tid) {
    const auto tgid = task_tgids.find(tid);
    return tgid == task_tgids.end() ? tid : tgid->second;
}

}  // namespace

void emit_signal_event(const TraceOptions& options, std::ostream& out,
                       const std::unordered_map<pid_t, pid_t>& task_tgids, std::uint64_t& sequence,
                       TraceResult& result, pid_t tid, int signal, bool delivered) {
    if (!options.signals) {
        return;
    }
    const pid_t pid = event_pid(task_tgids, tid);
    const std::uint64_t event_sequence = ++sequence;
    ++result.events;
    const char* description = ::strsignal(signal);
    if (options.json) {
        out << "{\"type\":\"signal\",\"pid\":" << pid << ",\"tid\":" << tid
            << ",\"seq\":" << event_sequence << ",\"signal\":{\"name\":\"" << signal_name(signal)
            << "\",\"number\":" << signal << ",\"description\":\""
            << escape_json(description == nullptr ? "" : description)
            << "\"},\"delivered\":" << (delivered ? "true" : "false") << "}\n";
        return;
    }
    if (options.follow_fork) {
        out << "[pid " << pid << "] ";
    }
    out << "signal(" << signal_name(signal) << ")" << (delivered ? " delivered" : " suppressed");
    if (description != nullptr) {
        out << " (" << description << ')';
    }
    out << '\n';
}

void emit_exit_event(const TraceOptions& options, std::ostream& out,
                     const std::unordered_map<pid_t, pid_t>& task_tgids, std::uint64_t& sequence,
                     TraceResult& result, pid_t primary_pid, pid_t tid, int status) {
    if (!options.lifecycle) {
        return;
    }
    const pid_t pid = event_pid(task_tgids, tid);
    const std::uint64_t event_sequence = ++sequence;
    ++result.events;
    const bool primary = tid == primary_pid;
    if (options.json) {
        out << "{\"type\":\"exit\",\"pid\":" << pid << ",\"tid\":" << tid
            << ",\"seq\":" << event_sequence << ",\"status\":" << status
            << ",\"primary\":" << (primary ? "true" : "false") << "}\n";
        return;
    }
    if (options.follow_fork) {
        out << "[pid " << pid << "] ";
    }
    out << "exit(status=" << status << ')' << (primary ? " primary" : " thread") << '\n';
}

void emit_signaled_event(const TraceOptions& options, std::ostream& out,
                         const std::unordered_map<pid_t, pid_t>& task_tgids,
                         std::uint64_t& sequence, TraceResult& result, pid_t primary_pid, pid_t tid,
                         int signal) {
    if (!options.lifecycle) {
        return;
    }
    const pid_t pid = event_pid(task_tgids, tid);
    const std::uint64_t event_sequence = ++sequence;
    ++result.events;
    const bool primary = tid == primary_pid;
    const char* description = ::strsignal(signal);
    if (options.json) {
        out << "{\"type\":\"signaled\",\"pid\":" << pid << ",\"tid\":" << tid
            << ",\"seq\":" << event_sequence << ",\"signal\":{\"name\":\"" << signal_name(signal)
            << "\",\"number\":" << signal << ",\"description\":\""
            << escape_json(description == nullptr ? "" : description)
            << "\"},\"primary\":" << (primary ? "true" : "false") << "}\n";
        return;
    }
    if (options.follow_fork) {
        out << "[pid " << pid << "] ";
    }
    out << "signaled(" << signal_name(signal) << ")";
    if (description != nullptr) {
        out << " (" << description << ')';
    }
    out << (primary ? " primary" : " thread") << '\n';
}

}  // namespace detail
}  // namespace mini_strace
