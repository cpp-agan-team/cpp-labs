#include "internal.hpp"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <optional>
#include <sstream>
#include <string>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <vector>

#ifndef SECCOMP_RET_ACTION_FULL
#define SECCOMP_RET_ACTION_FULL 0xffff0000U
#endif

#ifndef SECCOMP_RET_DATA
#define SECCOMP_RET_DATA 0x0000ffffU
#endif

namespace mini_strace {
namespace detail {
namespace {

struct NamedSyscall {
    std::string name;
    std::uint64_t nr = 0;
};

struct SeccompProgram {
    std::vector<NamedSyscall> syscalls;
    std::vector<sock_filter> code;
};

std::vector<NamedSyscall> named_syscalls_from_filters(
    const std::unordered_set<std::string>& filters) {
    std::vector<NamedSyscall> numbers;
    numbers.reserve(filters.size());
    for (const auto& name : filters) {
        std::uint64_t nr = 0;
        if (syscall_number_by_name(name, nr)) {
            numbers.push_back({name, nr});
        }
    }
    std::sort(numbers.begin(), numbers.end(), [](const NamedSyscall& lhs, const NamedSyscall& rhs) {
        if (lhs.nr != rhs.nr) {
            return lhs.nr < rhs.nr;
        }
        return lhs.name < rhs.name;
    });
    return numbers;
}

std::optional<SeccompProgram> build_trace_seccomp_program(
    const std::unordered_set<std::string>& filters) {
    SeccompProgram program;
    program.syscalls = named_syscalls_from_filters(filters);
    const auto& numbers = program.syscalls;
    if (numbers.empty() || numbers.size() > 200) {
        return std::nullopt;
    }

    auto& code = program.code;
    code.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)));
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    code.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    code.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)));
    for (const auto& syscall : numbers) {
        code.push_back(
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned int>(syscall.nr), 0, 1));
        code.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE));
    }
    code.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    return program;
}

std::string format_bpf_constant(std::uint32_t value) {
    if (value == AUDIT_ARCH_X86_64) {
        return "AUDIT_ARCH_X86_64";
    }
    const std::string name = syscall_name(value);
    if (name.rfind("sys_", 0) != 0) {
        return "SYS_" + name + "(" + std::to_string(value) + ")";
    }
    return format_hex(value);
}

std::string format_seccomp_ret(std::uint32_t value) {
    const std::uint32_t action = value & SECCOMP_RET_ACTION_FULL;
    const std::uint32_t data = value & SECCOMP_RET_DATA;
    switch (action) {
#ifdef SECCOMP_RET_KILL_PROCESS
        case SECCOMP_RET_KILL_PROCESS:
            return "SECCOMP_RET_KILL_PROCESS";
#endif
        case SECCOMP_RET_KILL:
            return "SECCOMP_RET_KILL";
        case SECCOMP_RET_TRAP:
            return "SECCOMP_RET_TRAP";
        case SECCOMP_RET_ERRNO:
            return "SECCOMP_RET_ERRNO(" + errno_name(static_cast<int>(data)) + ")";
        case SECCOMP_RET_TRACE:
            return data == 0 ? "SECCOMP_RET_TRACE"
                             : "SECCOMP_RET_TRACE(data=" + std::to_string(data) + ")";
#ifdef SECCOMP_RET_LOG
        case SECCOMP_RET_LOG:
            return "SECCOMP_RET_LOG";
#endif
        case SECCOMP_RET_ALLOW:
            return "SECCOMP_RET_ALLOW";
        default:
            return "SECCOMP_RET_" + format_hex(action) + "(data=" + std::to_string(data) + ")";
    }
}

std::string describe_bpf_instruction(const sock_filter& instruction) {
    const auto code = instruction.code;
    const auto klass = BPF_CLASS(code);
    std::ostringstream out;
    if (klass == BPF_LD && BPF_MODE(code) == BPF_ABS && BPF_SIZE(code) == BPF_W) {
        if (instruction.k == offsetof(seccomp_data, arch)) {
            return "ld [seccomp.arch]";
        }
        if (instruction.k == offsetof(seccomp_data, nr)) {
            return "ld [seccomp.nr]";
        }
        out << "ld [seccomp+" << instruction.k << ']';
        return out.str();
    }
    if (klass == BPF_JMP && BPF_OP(code) == BPF_JEQ) {
        out << "jeq " << format_bpf_constant(instruction.k) << " jt=+"
            << static_cast<int>(instruction.jt) << " jf=+" << static_cast<int>(instruction.jf);
        return out.str();
    }
    if (klass == BPF_RET) {
        out << "ret " << format_seccomp_ret(instruction.k);
        return out.str();
    }
    out << "code=" << format_hex(code) << " jt=" << static_cast<int>(instruction.jt)
        << " jf=" << static_cast<int>(instruction.jf) << " k=" << format_hex(instruction.k);
    return out.str();
}

void emit_seccomp_filter_dump(const TraceOptions& options, std::ostream& out,
                              std::uint64_t& sequence, const std::string& source, pid_t pid,
                              pid_t tid, std::size_t index, const std::vector<sock_filter>& code) {
    const std::uint64_t event_sequence = ++sequence;
    if (options.json) {
        out << "{\"type\":\"seccomp_filter\",\"source\":\"" << escape_json(source)
            << "\",\"seq\":" << event_sequence;
        if (pid > 0) {
            out << ",\"pid\":" << pid << ",\"tid\":" << tid;
        }
        out << ",\"index\":" << index << ",\"instruction_count\":" << code.size()
            << ",\"instructions\":[";
        for (std::size_t pc = 0; pc < code.size(); ++pc) {
            if (pc != 0) {
                out << ',';
            }
            const auto& instruction = code[pc];
            out << "{\"pc\":" << pc << ",\"code\":\"" << format_hex(instruction.code)
                << "\",\"jt\":" << static_cast<int>(instruction.jt)
                << ",\"jf\":" << static_cast<int>(instruction.jf) << ",\"k\":\""
                << format_hex(instruction.k) << "\",\"text\":\""
                << escape_json(describe_bpf_instruction(instruction)) << "\"}";
        }
        out << "]}\n";
        return;
    }

    out << "seccomp_filter(source=" << source;
    if (pid > 0) {
        out << ", pid=" << pid << ", tid=" << tid;
    }
    out << ", index=" << index << ", instructions=" << code.size() << ")\n";
    for (std::size_t pc = 0; pc < code.size(); ++pc) {
        out << "  " << std::setw(4) << std::setfill('0') << pc << std::setfill(' ') << ": "
            << describe_bpf_instruction(code[pc]) << '\n';
    }
}

void emit_seccomp_dump_unavailable(const TraceOptions& options, std::ostream& out,
                                   std::uint64_t& sequence, pid_t pid, pid_t tid,
                                   const std::string& reason) {
    const std::uint64_t event_sequence = ++sequence;
    if (options.json) {
        out << "{\"type\":\"seccomp_filter_unavailable\",\"pid\":" << pid << ",\"tid\":" << tid
            << ",\"seq\":" << event_sequence << ",\"reason\":\"" << escape_json(reason) << "\"}\n";
        return;
    }
    out << "seccomp_filter_unavailable(pid=" << pid << ", tid=" << tid << ", reason=" << reason
        << ")\n";
}

struct SeccompDumpAttempt {
    bool available = false;
    bool permanent_failure = false;
    std::string error;
    std::vector<std::vector<sock_filter>> filters;
};

SeccompDumpAttempt read_target_seccomp_filters(pid_t tid) {
    SeccompDumpAttempt attempt;
#ifdef PTRACE_SECCOMP_GET_FILTER
    constexpr std::size_t kMaxFilters = 32;
    constexpr long kMaxInstructions = 4096;
    for (std::size_t index = 0; index < kMaxFilters; ++index) {
        errno = 0;
        const long length =
            ::ptrace(PTRACE_SECCOMP_GET_FILTER, tid,
                     reinterpret_cast<void*>(static_cast<std::uintptr_t>(index)), nullptr);
        if (length < 0) {
            const int error = errno == 0 ? EIO : errno;
            if (index == 0 && (error == EPERM || error == EACCES || error == ENOSYS)) {
                attempt.permanent_failure = true;
                attempt.error = errno_name(error);
            }
            return attempt;
        }
        if (length == 0 || length > kMaxInstructions) {
            return attempt;
        }
        std::vector<sock_filter> code(static_cast<std::size_t>(length));
        errno = 0;
        const long copied =
            ::ptrace(PTRACE_SECCOMP_GET_FILTER, tid,
                     reinterpret_cast<void*>(static_cast<std::uintptr_t>(index)), code.data());
        if (copied < 0) {
            const int error = errno == 0 ? EIO : errno;
            attempt.permanent_failure = error == EPERM || error == EACCES || error == ENOSYS;
            attempt.error = errno_name(error);
            return attempt;
        }
        attempt.available = true;
        attempt.filters.push_back(std::move(code));
    }
    return attempt;
#else
    (void)tid;
    attempt.permanent_failure = true;
    attempt.error = "PTRACE_SECCOMP_GET_FILTER unavailable at build time";
    return attempt;
#endif
}

}  // namespace

int install_seccomp_filter(const std::unordered_set<std::string>& filters) {
    auto compiled = build_trace_seccomp_program(filters);
    if (!compiled) {
        return -1;
    }

    sock_fprog program{};
    program.len = static_cast<unsigned short>(compiled->code.size());
    program.filter = compiled->code.data();

    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return -1;
    }
    return ::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

void maybe_emit_generated_seccomp_filter_dump(const TraceOptions& options, std::ostream& out,
                                              std::uint64_t& sequence) {
    if (!options.seccomp_bpf || !options.dump_seccomp) {
        return;
    }
    const auto program = build_trace_seccomp_program(options.filters);
    if (!program) {
        return;
    }
    emit_seccomp_filter_dump(options, out, sequence, "generated", -1, -1, 0, program->code);
}

void maybe_dump_target_seccomp_filters(pid_t tid, const TraceOptions& options, std::ostream& out,
                                       const std::unordered_map<pid_t, pid_t>& task_tgids,
                                       SeccompDumpState& state, std::uint64_t& sequence) {
    if (!options.dump_seccomp) {
        return;
    }
    const auto tgid = task_tgids.find(tid);
    const pid_t pid = tgid == task_tgids.end() ? tid : tgid->second;
    if (state.dumped_tgids.find(pid) != state.dumped_tgids.end() ||
        state.failed_tgids.find(pid) != state.failed_tgids.end()) {
        return;
    }

    SeccompDumpAttempt attempt = read_target_seccomp_filters(tid);
    if (attempt.available) {
        for (std::size_t index = 0; index < attempt.filters.size(); ++index) {
            emit_seccomp_filter_dump(options, out, sequence, "target", pid, tid, index,
                                     attempt.filters[index]);
        }
        state.dumped_tgids.insert(pid);
        return;
    }
    if (attempt.permanent_failure) {
        emit_seccomp_dump_unavailable(options, out, sequence, pid, tid, attempt.error);
        state.failed_tgids.insert(pid);
    }
}

}  // namespace detail
}  // namespace mini_strace
