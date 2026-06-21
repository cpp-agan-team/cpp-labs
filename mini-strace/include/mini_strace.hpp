#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <sys/types.h>
#include <unordered_set>
#include <vector>

namespace mini_strace {

// Public API stability guide:
// - TraceOptions, TraceResult, SyscallEvent, DecodedArg, EventSink, run_trace(),
//   trace(), syscall_name(), syscall_number_by_name(), and errno_name() are the
//   long-term library surface.
// - FdContext, VmaContext, SeccompContext, Diagnosis, and InjectionRule are kept
//   public because they are already embedded in SyscallEvent or TraceOptions.
//   Treat their contents as best-effort context rather than kernel truth; later
//   additions should prefer optional fields or a versioned event type over
//   changing existing field meanings.

enum class TraceMode {
    Launch,
    Attach,
};

enum class ArgReadStatus {
    NotRead,
    Ok,
    NullPointer,
    Unreadable,
    Truncated,
};

struct DecodedArg {
    std::string name;
    std::string value;
    std::uint64_t raw = 0;
    ArgReadStatus read_status = ArgReadStatus::NotRead;
    std::string read_error;
};

// Best-effort fd context inferred from observed syscalls and /proc seeding.
// It is useful for diagnostics, but it is not a stable replacement for kernel
// fd-table truth at an arbitrary point in time.
struct FdContext {
    int fd = -1;
    std::string kind;
    std::string path;
    std::string peer;
    bool close_on_exec = false;
    bool known = false;
    std::string source;
};

// Best-effort VMA context inferred from mmap/brk/mprotect/munmap events.
// Attach mode may depend on /proc maps seeding before later events are observed.
struct VmaContext {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
    std::string perms;
    std::string source;
    bool known = false;
};

// Seccomp metadata is present only when ptrace/seccomp exposes it. A syscall can
// still be affected by seccomp without producing this context, for example with
// SECCOMP_RET_ERRNO rules that return directly from the kernel.
struct SeccompContext {
    bool ptrace_event = false;
    std::string action;
    std::uint32_t ret_data = 0;
};

// Candidate diagnosis attached by optional analyzers such as --explain-deny.
// It is evidence-based guidance, not a final policy verdict.
struct Diagnosis {
    std::string category;
    std::string confidence;
    std::vector<std::string> evidence;
    std::string hint;
};

// Stable syscall event envelope delivered to EventSink and JSON/text formatters.
// New optional context may be added over time, but existing field meanings should
// remain compatible with docs/json-schema.md.
struct SyscallEvent {
    pid_t pid = -1;
    pid_t tid = -1;
    std::uint64_t sequence = 0;
    std::uint64_t nr = 0;
    std::string name;
    std::array<std::uint64_t, 6> raw_args{};
    std::vector<DecodedArg> decoded_args;
    std::uint64_t enter_ns = 0;
    std::uint64_t exit_ns = 0;
    std::uint64_t duration_ns = 0;
    std::int64_t raw_ret = 0;
    bool is_error = false;
    int errno_value = 0;
    std::string errno_name;
    std::string errno_message;
    std::optional<FdContext> fd_context;
    std::optional<VmaContext> vma_context;
    std::optional<SeccompContext> seccomp_context;
    std::optional<Diagnosis> diagnosis;
    bool interrupted = false;
    bool injected = false;
    int injected_errno_value = 0;
    std::string injected_errno_name;
};

class EventSink {
public:
    virtual ~EventSink() = default;
    virtual void on_syscall(const SyscallEvent& event) = 0;
};

// Error injection rule used by TraceOptions::injections. It is intentionally
// narrow: mini-strace currently supports errno injection at syscall boundaries.
struct InjectionRule {
    std::string syscall;
    std::uint64_t syscall_nr = 0;
    int errno_value = 0;
    std::size_t when = 0;  // 0 means every matching syscall.
};

// TraceOptions is the stable programmatic equivalent of the CLI flags. Keep
// added options additive and preserve existing defaults so run_trace()/trace()
// callers are not surprised by a library upgrade.
struct TraceOptions {
    TraceMode mode = TraceMode::Launch;
    pid_t attach_pid = -1;
    std::vector<std::string> command;
    std::unordered_set<std::string> filters;
    std::vector<InjectionRule> injections;
    bool follow_fork = false;
    bool json = false;
    bool summary = false;
    bool raw = false;
    bool show_state = false;
    bool diagnose = false;
    bool seccomp_bpf = false;
    bool dump_seccomp = false;
    bool signals = false;
    bool lifecycle = false;
    bool io_latency = false;
    bool net = false;
    bool explain_deny = false;
    bool process = false;
    std::uint64_t slow_io_threshold_us = 1000;
    std::size_t string_limit = 64;
    std::size_t max_events = 0;
};

// Result metadata for the traced primary task plus the number of emitted syscall
// events. Lifecycle/signal helper events are intentionally reported through the
// output stream rather than expanding this struct.
struct TraceResult {
    int exit_code = 0;
    bool signaled = false;
    int term_signal = 0;
    std::size_t events = 0;
};

TraceResult run_trace(const TraceOptions& options, std::ostream& out, std::ostream& err);
TraceResult trace(const TraceOptions& options, EventSink& sink, std::ostream& err);

std::string syscall_name(std::uint64_t nr);
bool syscall_number_by_name(const std::string& name, std::uint64_t& nr);
std::string errno_name(int value);

}  // namespace mini_strace
