#pragma once

#include "mini_strace.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

struct user_regs_struct;

namespace mini_strace {
namespace detail {

using mini_strace::ArgReadStatus;
using mini_strace::DecodedArg;
using mini_strace::Diagnosis;
using mini_strace::FdContext;
using mini_strace::SeccompContext;
using mini_strace::SyscallEvent;
using mini_strace::VmaContext;

struct PendingSyscall {
    bool active = false;
    SyscallEvent event;
};

struct ThreadState {
    PendingSyscall pending;
};

struct RemoteBytes {
    std::vector<unsigned char> data;
    ArgReadStatus status = ArgReadStatus::NotRead;
    std::string error;
    bool truncated = false;
};

struct SyscallStats {
    std::uint64_t count = 0;
    std::uint64_t errors = 0;
    std::uint64_t total_ns = 0;
    std::uint64_t max_ns = 0;
};

class StateTracker {
public:
    void seed_from_proc(pid_t pid);
    void on_exec();
    void enrich_before(SyscallEvent& event) const;
    void apply(SyscallEvent& event);

private:
    std::unordered_map<int, FdContext> fds_;
    std::vector<VmaContext> vmas_;
    std::uint64_t current_brk_ = 0;
};

class Summary {
public:
    void observe(const SyscallEvent& event);
    void write(std::ostream& out) const;
    void write_diagnostics(std::ostream& out) const;

private:
    std::map<std::string, SyscallStats> stats_;
    std::map<std::string, std::uint64_t> path_misses_;
    std::map<std::string, std::uint64_t> fd_writes_;
    std::int64_t mmap_delta_ = 0;
    std::uint64_t futex_wait_count_ = 0;
    std::uint64_t futex_wait_errors_ = 0;
    std::uint64_t futex_wait_total_ns_ = 0;
    std::uint64_t futex_wait_max_ns_ = 0;
    std::map<std::string, std::uint64_t> interrupted_syscalls_;
    std::uint64_t restart_syscall_count_ = 0;
};

struct IoLatencyStats {
    std::uint64_t count = 0;
    std::uint64_t errors = 0;
    std::uint64_t slow = 0;
    std::uint64_t total_ns = 0;
    std::uint64_t max_ns = 0;
};

class IoLatencySummary {
public:
    explicit IoLatencySummary(std::uint64_t slow_threshold_us);
    void observe(const SyscallEvent& event);
    void write(std::ostream& out) const;

private:
    std::uint64_t slow_threshold_ns_ = 0;
    std::map<std::string, IoLatencyStats> by_syscall_;
    std::map<std::string, IoLatencyStats> by_fd_;
    std::map<std::string, IoLatencyStats> by_path_;
};

struct NetworkSyscallStats {
    std::uint64_t count = 0;
    std::uint64_t errors = 0;
    std::uint64_t total_ns = 0;
    std::uint64_t max_ns = 0;
};

struct SocketSummary {
    pid_t pid = -1;
    int fd = -1;
    std::string domain;
    std::string type;
    std::string protocol;
    std::string local;
    std::string peer;
    std::vector<std::string> options;
    std::uint64_t sent_bytes = 0;
    std::uint64_t recv_bytes = 0;
    std::uint64_t send_calls = 0;
    std::uint64_t recv_calls = 0;
    std::uint64_t errors = 0;
};

class NetworkSummary {
public:
    void observe(const SyscallEvent& event);
    void write(std::ostream& out) const;

private:
    std::map<std::pair<pid_t, int>, SocketSummary> sockets_;
    std::map<std::string, NetworkSyscallStats> syscalls_;
};

class DenyExplainer {
public:
    std::optional<Diagnosis> explain(const SyscallEvent& event) const;
};

struct ProcessResourceStats {
    std::uint64_t count = 0;
    std::uint64_t errors = 0;
};

struct ProcessChild {
    pid_t parent = -1;
    pid_t child = -1;
    std::string source;
};

struct ProcessWait {
    pid_t parent = -1;
    pid_t child = -1;
    std::string status;
};

class ProcessSummary {
public:
    void observe(const SyscallEvent& event);
    void write(std::ostream& out) const;

private:
    std::uint64_t fork_events_ = 0;
    std::uint64_t clone_events_ = 0;
    std::uint64_t exec_events_ = 0;
    std::uint64_t wait_events_ = 0;
    std::uint64_t errors_ = 0;
    std::vector<ProcessChild> children_;
    std::vector<ProcessWait> waits_;
    std::map<std::string, ProcessResourceStats> resources_;
};

struct SeccompDumpState {
    std::set<pid_t> dumped_tgids;
    std::set<pid_t> failed_tgids;
};

std::uint64_t now_ns();
std::string escape_text(const std::string& input);
std::string escape_json(const std::string& input);
std::string format_hex(std::uint64_t value);
std::string format_errno_message(int value);
std::string format_operation_error(const std::string& operation, int error);

RemoteBytes read_remote_bytes(pid_t pid, std::uint64_t address, std::size_t max_bytes);
DecodedArg read_remote_string_arg(pid_t pid, const std::string& name, std::uint64_t address,
                                  std::size_t limit);
DecodedArg read_remote_buffer_arg(pid_t pid, const std::string& name, std::uint64_t address,
                                  std::size_t limit);

void apply_entry_injection(pid_t tid, user_regs_struct& regs, SyscallEvent& event,
                           const TraceOptions& options,
                           std::unordered_map<std::string, std::size_t>& injection_seen);
void apply_exit_injection(pid_t tid, user_regs_struct& regs, const SyscallEvent& event);
std::vector<pid_t> enumerate_tids(pid_t pid);
void ptrace_attach_checked(int request, pid_t pid, pid_t tid, void* data,
                           const std::string& operation);
void set_trace_options(pid_t pid, bool launched_by_us, bool follow_fork, bool seccomp_bpf);
int install_seccomp_filter(const std::unordered_set<std::string>& filters);
void maybe_emit_generated_seccomp_filter_dump(const TraceOptions& options, std::ostream& out,
                                              std::uint64_t& sequence);
void maybe_dump_target_seccomp_filters(pid_t tid, const TraceOptions& options, std::ostream& out,
                                       const std::unordered_map<pid_t, pid_t>& task_tgids,
                                       SeccompDumpState& state, std::uint64_t& sequence);
void emit_signal_event(const TraceOptions& options, std::ostream& out,
                       const std::unordered_map<pid_t, pid_t>& task_tgids, std::uint64_t& sequence,
                       TraceResult& result, pid_t tid, int signal, bool delivered);
void emit_exit_event(const TraceOptions& options, std::ostream& out,
                     const std::unordered_map<pid_t, pid_t>& task_tgids, std::uint64_t& sequence,
                     TraceResult& result, pid_t primary_pid, pid_t tid, int status);
void emit_signaled_event(const TraceOptions& options, std::ostream& out,
                         const std::unordered_map<pid_t, pid_t>& task_tgids,
                         std::uint64_t& sequence, TraceResult& result, pid_t primary_pid, pid_t tid,
                         int signal);
std::string format_event_text(const SyscallEvent& event, bool raw, bool show_state,
                              bool prefix_pid);
std::string format_event_json(const SyscallEvent& event);

}  // namespace detail
}  // namespace mini_strace
