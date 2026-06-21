#include "internal.hpp"

#include <cerrno>
#include <stdexcept>
#include <string>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>

namespace mini_strace {
namespace detail {
namespace {

std::runtime_error syscall_error(const std::string& what) {
    return std::runtime_error(format_operation_error(what, errno));
}

void ptrace_setregs_checked(pid_t tid, user_regs_struct& regs, const std::string& what) {
    errno = 0;
    if (::ptrace(PTRACE_SETREGS, tid, nullptr, &regs) == -1) {
        if (errno == 0) {
            errno = EIO;
        }
        throw syscall_error(what);
    }
}

const InjectionRule* matching_injection(
    const TraceOptions& options, std::unordered_map<std::string, std::size_t>& injection_seen,
    const SyscallEvent& event) {
    if (options.injections.empty()) {
        return nullptr;
    }
    std::size_t seen = 0;
    for (const auto& rule : options.injections) {
        if (rule.syscall_nr == event.nr) {
            if (seen == 0) {
                seen = ++injection_seen[event.name];
            }
            if (rule.when == 0 || rule.when == seen) {
                return &rule;
            }
        }
    }
    return nullptr;
}

}  // namespace

void apply_entry_injection(pid_t tid, user_regs_struct& regs, SyscallEvent& event,
                           const TraceOptions& options,
                           std::unordered_map<std::string, std::size_t>& injection_seen) {
    const auto* rule = matching_injection(options, injection_seen, event);
    if (rule == nullptr) {
        return;
    }
    event.injected = true;
    event.injected_errno_value = rule->errno_value;
    event.injected_errno_name = errno_name(rule->errno_value);
    regs.orig_rax = static_cast<unsigned long long>(-1LL);
    ptrace_setregs_checked(tid, regs, "PTRACE_SETREGS inject entry");
}

void apply_exit_injection(pid_t tid, user_regs_struct& regs, const SyscallEvent& event) {
    if (!event.injected) {
        return;
    }
    regs.rax = static_cast<unsigned long long>(-static_cast<long long>(event.injected_errno_value));
    ptrace_setregs_checked(tid, regs, "PTRACE_SETREGS inject exit");
}

}  // namespace detail
}  // namespace mini_strace
