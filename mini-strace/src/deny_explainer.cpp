#include "internal.hpp"

#include <cerrno>
#include <optional>
#include <string>
#include <vector>

namespace mini_strace {
namespace detail {
namespace {

bool is_interesting_errno(int value) {
    switch (value) {
        case EPERM:
        case EACCES:
        case ENOSYS:
        case EINVAL:
        case ENOENT:
        case ENOTDIR:
        case ELOOP:
        case EISDIR:
        case EROFS:
            return true;
        default:
            return false;
    }
}

bool is_path_syscall(const std::string& name) {
    return name == "open" || name == "openat" || name == "openat2" || name == "creat" ||
           name == "execve" || name == "statx" || name == "newfstatat";
}

bool syscall_usually_cannot_fail_with_eperm(const std::string& name) {
    return name == "getpid" || name == "gettid" || name == "getppid" || name == "getuid" ||
           name == "geteuid" || name == "getgid" || name == "getegid";
}

std::optional<std::string> decoded_arg_value(const SyscallEvent& event, const std::string& name) {
    for (const auto& arg : event.decoded_args) {
        if (arg.name == name && !arg.value.empty()) {
            return arg.value;
        }
    }
    return std::nullopt;
}

Diagnosis base_diagnosis(const SyscallEvent& event, const std::string& category,
                         const std::string& confidence, const std::string& hint) {
    Diagnosis diagnosis;
    diagnosis.category = category;
    diagnosis.confidence = confidence;
    diagnosis.hint = hint;
    diagnosis.evidence.push_back("syscall=" + event.name);
    diagnosis.evidence.push_back("errno=" + event.errno_name);
    return diagnosis;
}

std::optional<Diagnosis> explain_injected(const SyscallEvent& event) {
    if (!event.injected) {
        return std::nullopt;
    }
    auto diagnosis = base_diagnosis(
        event, "injected_fault", "high",
        "The tracer injected this error; it is not the kernel's original syscall result.");
    diagnosis.evidence.push_back("injected_errno=" + event.injected_errno_name);
    return diagnosis;
}

std::optional<Diagnosis> explain_seccomp_context(const SyscallEvent& event) {
    if (!event.seccomp_context) {
        return std::nullopt;
    }
    auto diagnosis = base_diagnosis(
        event, "maybe_seccomp", "high",
        "A ptrace seccomp stop was observed around this syscall; check the active seccomp policy.");
    diagnosis.evidence.push_back("seccomp_action=" + event.seccomp_context->action);
    diagnosis.evidence.push_back("seccomp_ret_data=" +
                                 std::to_string(event.seccomp_context->ret_data));
    return diagnosis;
}

std::optional<Diagnosis> explain_seccomp_errno_candidate(const SyscallEvent& event) {
    if ((event.errno_value != EPERM && event.errno_value != ENOSYS) ||
        !syscall_usually_cannot_fail_with_eperm(event.name)) {
        return std::nullopt;
    }
    auto diagnosis = base_diagnosis(
        event, "maybe_seccomp", "medium",
        "This syscall normally does not fail this way; a seccomp ERRNO rule is a likely cause.");
    diagnosis.evidence.push_back("syscall_normally_cannot_fail_with_" + event.errno_name);
    diagnosis.evidence.push_back("seccomp_errno_may_not_emit_ptrace_event");
    return diagnosis;
}

std::optional<Diagnosis> explain_path_access(const SyscallEvent& event) {
    if (!is_path_syscall(event.name)) {
        return std::nullopt;
    }
    const auto pathname = decoded_arg_value(event, "pathname");
    if (!pathname) {
        return std::nullopt;
    }
    if (event.errno_value == ENOENT || event.errno_value == ENOTDIR || event.errno_value == ELOOP) {
        auto diagnosis =
            base_diagnosis(event, "missing_path", "medium",
                           "The path lookup failed before the syscall could act on it.");
        diagnosis.evidence.push_back("pathname=" + *pathname);
        return diagnosis;
    }
    if (event.errno_value == EACCES || event.errno_value == EPERM || event.errno_value == EISDIR ||
        event.errno_value == EROFS) {
        auto diagnosis =
            base_diagnosis(event, "path_access", "medium",
                           "The pathname or mount policy likely denied this filesystem operation.");
        diagnosis.evidence.push_back("pathname=" + *pathname);
        return diagnosis;
    }
    return std::nullopt;
}

std::optional<Diagnosis> explain_invalid_argument(const SyscallEvent& event) {
    if (event.errno_value != EINVAL) {
        return std::nullopt;
    }
    auto diagnosis = base_diagnosis(
        event, "invalid_argument", "medium",
        "The kernel rejected one of the syscall arguments, flags, sizes, or structure fields.");
    if (const auto flags = decoded_arg_value(event, "flags")) {
        diagnosis.evidence.push_back("flags=" + *flags);
    }
    if (const auto size = decoded_arg_value(event, "size")) {
        diagnosis.evidence.push_back("size=" + *size);
    }
    return diagnosis;
}

std::optional<Diagnosis> explain_policy_or_capability(const SyscallEvent& event) {
    if (event.errno_value == EPERM || event.errno_value == EACCES) {
        return base_diagnosis(event, "permission_policy", "low",
                              "The syscall was denied by credentials, capabilities, LSM, mount "
                              "policy, or sandboxing.");
    }
    if (event.errno_value == ENOSYS) {
        return base_diagnosis(
            event, "syscall_unavailable", "low",
            "The syscall may be unsupported by the kernel or filtered to look unavailable.");
    }
    return std::nullopt;
}

}  // namespace

std::optional<Diagnosis> DenyExplainer::explain(const SyscallEvent& event) const {
    if (!event.is_error) {
        return std::nullopt;
    }
    if (auto diagnosis = explain_injected(event)) {
        return diagnosis;
    }
    if (!is_interesting_errno(event.errno_value)) {
        return std::nullopt;
    }
    if (auto diagnosis = explain_seccomp_context(event)) {
        return diagnosis;
    }
    if (auto diagnosis = explain_seccomp_errno_candidate(event)) {
        return diagnosis;
    }
    if (auto diagnosis = explain_path_access(event)) {
        return diagnosis;
    }
    if (auto diagnosis = explain_invalid_argument(event)) {
        return diagnosis;
    }
    return explain_policy_or_capability(event);
}

}  // namespace detail
}  // namespace mini_strace
