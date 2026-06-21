#include "internal.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/ptrace.h>
#include <system_error>
#include <unistd.h>

namespace mini_strace {
namespace detail {
namespace {

std::runtime_error syscall_error(const std::string& what) {
    return std::runtime_error(format_operation_error(what, errno));
}

long ptrace_checked(enum __ptrace_request request, pid_t pid, void* addr, void* data,
                    const std::string& what) {
    errno = 0;
    const long rc = ::ptrace(request, pid, addr, data);
    if (rc == -1) {
        if (errno == 0) {
            errno = EIO;
        }
        throw syscall_error(what);
    }
    return rc;
}

std::string read_ptrace_scope() {
    std::ifstream in("/proc/sys/kernel/yama/ptrace_scope");
    std::string value;
    if (in >> value) {
        return value;
    }
    return "unavailable";
}

std::runtime_error attach_error(pid_t pid, pid_t tid, const std::string& operation, int error) {
    std::ostringstream out;
    out << operation << " failed for pid " << pid;
    if (tid != pid) {
        out << " tid " << tid;
    }
    out << ": " << format_errno_message(error) << " (errno=" << errno_name(error) << '/' << error
        << ')';
    if (error == ESRCH) {
        out << "\n  hint: target process does not exist, exited, or the thread disappeared during "
               "attach";
    } else if (error == EPERM || error == EACCES) {
        out << "\n  hint: attach permission was denied"
            << "\n  possible causes:"
            << "\n    - target uid differs from tracer uid"
            << "\n    - /proc/sys/kernel/yama/ptrace_scope is " << read_ptrace_scope()
            << "\n    - missing CAP_SYS_PTRACE"
            << "\n  hint: try sudo mini-strace --pid " << pid
            << "\n  hint: or temporarily lower yama with: echo 0 | sudo tee "
               "/proc/sys/kernel/yama/ptrace_scope";
    }
    return std::runtime_error(out.str());
}

}  // namespace

std::vector<pid_t> enumerate_tids(pid_t pid) {
    std::vector<pid_t> tids;
    const std::filesystem::path task_dir =
        std::filesystem::path("/proc") / std::to_string(pid) / "task";
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(task_dir, ec)) {
        if (ec) {
            break;
        }
        const std::string name = entry.path().filename().string();
        char* end = nullptr;
        const long tid = std::strtol(name.c_str(), &end, 10);
        if (end != name.c_str() && *end == '\0' && tid > 0) {
            tids.push_back(static_cast<pid_t>(tid));
        }
    }
    if (tids.empty()) {
        tids.push_back(pid);
    }
    return tids;
}

void ptrace_attach_checked(int request, pid_t pid, pid_t tid, void* data,
                           const std::string& operation) {
    errno = 0;
    if (::ptrace(static_cast<enum __ptrace_request>(request), tid, nullptr, data) == -1) {
        throw attach_error(pid, tid, operation, errno == 0 ? EIO : errno);
    }
}

void set_trace_options(pid_t pid, bool launched_by_us, bool follow_fork, bool seccomp_bpf) {
    long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC;
    if (launched_by_us) {
        options |= PTRACE_O_EXITKILL;
    }
    if (follow_fork) {
        options |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE;
    }
    if (seccomp_bpf) {
        options |= PTRACE_O_TRACESECCOMP;
    }
    ptrace_checked(PTRACE_SETOPTIONS, pid, nullptr,
                   reinterpret_cast<void*>(static_cast<std::uintptr_t>(options)),
                   "PTRACE_SETOPTIONS");
}

}  // namespace detail
}  // namespace mini_strace
