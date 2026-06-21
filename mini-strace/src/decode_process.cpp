#include "decoder_internal.hpp"

#include <algorithm>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <sched.h>
#include <sstream>
#include <string>
#include <sys/resource.h>
#include <sys/wait.h>
#include <utility>
#include <vector>

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE (1U << 1)
#endif

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

namespace mini_strace {
namespace detail {
namespace {

std::string format_fd(std::uint64_t value) {
    return std::to_string(static_cast<long long>(value));
}

std::string format_dirfd(std::uint64_t value) {
    if (static_cast<int>(value) == AT_FDCWD) {
        return "AT_FDCWD";
    }
    return format_fd(value);
}

std::string flag_list(std::uint64_t value,
                      const std::vector<std::pair<std::uint64_t, const char*>>& flags,
                      std::uint64_t known) {
    std::vector<std::string> parts;
    for (const auto& flag : flags) {
        if ((value & flag.first) == flag.first) {
            parts.emplace_back(flag.second);
        }
    }
    const std::uint64_t unknown = value & ~known;
    if (unknown != 0) {
        parts.push_back(format_hex(unknown));
    }
    if (parts.empty()) {
        return "0";
    }
    std::ostringstream out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) {
            out << '|';
        }
        out << parts[i];
    }
    return out.str();
}

std::string format_string_vector(pid_t pid, std::uint64_t address, std::size_t string_limit) {
    constexpr std::size_t kMaxItems = 4;
    if (address == 0) {
        return "NULL";
    }
    const auto bytes = read_remote_bytes(pid, address, sizeof(std::uint64_t) * (kMaxItems + 1));
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.size() < sizeof(std::uint64_t)) {
        return format_hex(address);
    }

    std::ostringstream out;
    out << '[';
    bool closed = false;
    const std::size_t entries = bytes.data.size() / sizeof(std::uint64_t);
    for (std::size_t i = 0; i < std::min(entries, kMaxItems + 1); ++i) {
        std::uint64_t pointer = 0;
        std::memcpy(&pointer, bytes.data.data() + i * sizeof(pointer), sizeof(pointer));
        if (pointer == 0) {
            closed = true;
            break;
        }
        if (i >= kMaxItems) {
            break;
        }
        if (i != 0) {
            out << ", ";
        }
        out << read_remote_string_arg(pid, "arg", pointer, string_limit).value;
    }
    if (!closed) {
        if (entries > 0) {
            out << ", ";
        }
        out << "...";
    }
    out << ']';
    return out.str();
}

std::string format_clone_flags(std::uint64_t flags) {
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> values = {
#ifdef CLONE_VM
        {CLONE_VM, "CLONE_VM"},
#endif
#ifdef CLONE_FS
        {CLONE_FS, "CLONE_FS"},
#endif
#ifdef CLONE_FILES
        {CLONE_FILES, "CLONE_FILES"},
#endif
#ifdef CLONE_SIGHAND
        {CLONE_SIGHAND, "CLONE_SIGHAND"},
#endif
#ifdef CLONE_PIDFD
        {CLONE_PIDFD, "CLONE_PIDFD"},
#endif
#ifdef CLONE_PTRACE
        {CLONE_PTRACE, "CLONE_PTRACE"},
#endif
#ifdef CLONE_VFORK
        {CLONE_VFORK, "CLONE_VFORK"},
#endif
#ifdef CLONE_PARENT
        {CLONE_PARENT, "CLONE_PARENT"},
#endif
#ifdef CLONE_THREAD
        {CLONE_THREAD, "CLONE_THREAD"},
#endif
#ifdef CLONE_NEWNS
        {CLONE_NEWNS, "CLONE_NEWNS"},
#endif
#ifdef CLONE_SYSVSEM
        {CLONE_SYSVSEM, "CLONE_SYSVSEM"},
#endif
#ifdef CLONE_SETTLS
        {CLONE_SETTLS, "CLONE_SETTLS"},
#endif
#ifdef CLONE_PARENT_SETTID
        {CLONE_PARENT_SETTID, "CLONE_PARENT_SETTID"},
#endif
#ifdef CLONE_CHILD_CLEARTID
        {CLONE_CHILD_CLEARTID, "CLONE_CHILD_CLEARTID"},
#endif
#ifdef CLONE_CHILD_SETTID
        {CLONE_CHILD_SETTID, "CLONE_CHILD_SETTID"},
#endif
#ifdef CLONE_NEWCGROUP
        {CLONE_NEWCGROUP, "CLONE_NEWCGROUP"},
#endif
#ifdef CLONE_NEWUTS
        {CLONE_NEWUTS, "CLONE_NEWUTS"},
#endif
#ifdef CLONE_NEWIPC
        {CLONE_NEWIPC, "CLONE_NEWIPC"},
#endif
#ifdef CLONE_NEWUSER
        {CLONE_NEWUSER, "CLONE_NEWUSER"},
#endif
#ifdef CLONE_NEWPID
        {CLONE_NEWPID, "CLONE_NEWPID"},
#endif
#ifdef CLONE_NEWNET
        {CLONE_NEWNET, "CLONE_NEWNET"},
#endif
    };
    for (const auto& flag : values) {
        known |= flag.first;
    }
    std::string result = flag_list(flags & ~0xffULL, values, known);
    const int signal = static_cast<int>(flags & 0xffU);
    if (signal == SIGCHLD) {
        result += result == "0" ? "SIGCHLD" : "|SIGCHLD";
    } else if (signal != 0) {
        result += result == "0" ? std::to_string(signal) : "|" + std::to_string(signal);
    }
    return result;
}

std::string format_clone3_args(pid_t pid, std::uint64_t address, std::uint64_t size) {
    if (address == 0) {
        return "NULL";
    }
    if (size == 0) {
        return format_hex(address);
    }
    const std::size_t read_len =
        static_cast<std::size_t>(std::min<std::uint64_t>(size, sizeof(clone_args)));
    const auto bytes = read_remote_bytes(pid, address, read_len);
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.empty()) {
        return "<unreadable>";
    }
    clone_args args{};
    std::memcpy(&args, bytes.data.data(), std::min(bytes.data.size(), sizeof(args)));
    std::ostringstream out;
    out << "{flags=" << format_clone_flags(args.flags) << ", pidfd=" << format_hex(args.pidfd)
        << ", child_tid=" << format_hex(args.child_tid)
        << ", parent_tid=" << format_hex(args.parent_tid) << ", exit_signal=" << args.exit_signal
        << ", stack=" << format_hex(args.stack) << ", stack_size=" << args.stack_size
        << ", tls=" << format_hex(args.tls);
    if (size > sizeof(clone_args)) {
        out << ", size=" << size;
    }
    out << '}';
    return out.str();
}

std::string format_wait_options(std::uint64_t options) {
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> values = {
#ifdef WNOHANG
        {WNOHANG, "WNOHANG"},
#endif
#ifdef WUNTRACED
        {WUNTRACED, "WUNTRACED"},
#endif
#ifdef WCONTINUED
        {WCONTINUED, "WCONTINUED"},
#endif
#ifdef __WNOTHREAD
        {__WNOTHREAD, "__WNOTHREAD"},
#endif
#ifdef __WCLONE
        {__WCLONE, "__WCLONE"},
#endif
#ifdef __WALL
        {__WALL, "__WALL"},
#endif
    };
    for (const auto& flag : values) {
        known |= flag.first;
    }
    return flag_list(options, values, known);
}

std::string format_wait_status(pid_t pid, std::uint64_t address, bool succeeded) {
    if (address == 0) {
        return "NULL";
    }
    if (!succeeded) {
        return format_hex(address);
    }
    const auto bytes = read_remote_bytes(pid, address, sizeof(int));
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.size() < sizeof(int)) {
        return format_hex(address);
    }
    int status = 0;
    std::memcpy(&status, bytes.data.data(), sizeof(status));
    std::ostringstream out;
    out << '{';
    if (WIFEXITED(status)) {
        out << "WIFEXITED, status=" << WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        out << "WIFSIGNALED, signal=" << WTERMSIG(status);
    } else if (WIFSTOPPED(status)) {
        out << "WIFSTOPPED, signal=" << WSTOPSIG(status);
#ifdef WIFCONTINUED
    } else if (WIFCONTINUED(status)) {
        out << "WIFCONTINUED";
#endif
    } else {
        out << "raw=" << status;
    }
    out << '}';
    return out.str();
}

std::string format_at_flags(std::uint64_t flags) {
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> values = {
#ifdef AT_EMPTY_PATH
        {AT_EMPTY_PATH, "AT_EMPTY_PATH"},
#endif
#ifdef AT_SYMLINK_NOFOLLOW
        {AT_SYMLINK_NOFOLLOW, "AT_SYMLINK_NOFOLLOW"},
#endif
#ifdef AT_NO_AUTOMOUNT
        {AT_NO_AUTOMOUNT, "AT_NO_AUTOMOUNT"},
#endif
#ifdef AT_STATX_FORCE_SYNC
        {AT_STATX_FORCE_SYNC, "AT_STATX_FORCE_SYNC"},
#endif
#ifdef AT_STATX_DONT_SYNC
        {AT_STATX_DONT_SYNC, "AT_STATX_DONT_SYNC"},
#endif
    };
    for (const auto& flag : values) {
        known |= flag.first;
    }
    return flag_list(flags, values, known);
}

std::string format_statx_mask(std::uint64_t mask) {
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> values = {
#ifdef STATX_TYPE
        {STATX_TYPE, "STATX_TYPE"},
#endif
#ifdef STATX_MODE
        {STATX_MODE, "STATX_MODE"},
#endif
#ifdef STATX_NLINK
        {STATX_NLINK, "STATX_NLINK"},
#endif
#ifdef STATX_UID
        {STATX_UID, "STATX_UID"},
#endif
#ifdef STATX_GID
        {STATX_GID, "STATX_GID"},
#endif
#ifdef STATX_ATIME
        {STATX_ATIME, "STATX_ATIME"},
#endif
#ifdef STATX_MTIME
        {STATX_MTIME, "STATX_MTIME"},
#endif
#ifdef STATX_CTIME
        {STATX_CTIME, "STATX_CTIME"},
#endif
#ifdef STATX_INO
        {STATX_INO, "STATX_INO"},
#endif
#ifdef STATX_SIZE
        {STATX_SIZE, "STATX_SIZE"},
#endif
#ifdef STATX_BLOCKS
        {STATX_BLOCKS, "STATX_BLOCKS"},
#endif
#ifdef STATX_BTIME
        {STATX_BTIME, "STATX_BTIME"},
#endif
    };
    for (const auto& flag : values) {
        known |= flag.first;
    }
    return flag_list(mask, values, known);
}

std::string format_rlimit_resource(std::uint64_t resource) {
    switch (static_cast<int>(resource)) {
        case RLIMIT_CPU:
            return "RLIMIT_CPU";
        case RLIMIT_FSIZE:
            return "RLIMIT_FSIZE";
        case RLIMIT_DATA:
            return "RLIMIT_DATA";
        case RLIMIT_STACK:
            return "RLIMIT_STACK";
        case RLIMIT_CORE:
            return "RLIMIT_CORE";
        case RLIMIT_NOFILE:
            return "RLIMIT_NOFILE";
        case RLIMIT_AS:
            return "RLIMIT_AS";
#ifdef RLIMIT_NPROC
        case RLIMIT_NPROC:
            return "RLIMIT_NPROC";
#endif
#ifdef RLIMIT_MEMLOCK
        case RLIMIT_MEMLOCK:
            return "RLIMIT_MEMLOCK";
#endif
#ifdef RLIMIT_RSS
        case RLIMIT_RSS:
            return "RLIMIT_RSS";
#endif
        default:
            return std::to_string(resource);
    }
}

std::string format_rlim_value(rlim_t value) {
    if (value == RLIM_INFINITY) {
        return "unlimited";
    }
    return std::to_string(static_cast<unsigned long long>(value));
}

std::string format_rlimit(pid_t pid, std::uint64_t address) {
    if (address == 0) {
        return "NULL";
    }
    const auto bytes = read_remote_bytes(pid, address, sizeof(rlimit));
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.size() < sizeof(rlimit)) {
        return format_hex(address);
    }
    rlimit limit{};
    std::memcpy(&limit, bytes.data.data(), sizeof(limit));
    return "{cur=" + format_rlim_value(limit.rlim_cur) +
           ", max=" + format_rlim_value(limit.rlim_max) + "}";
}

std::string format_close_range_flags(std::uint64_t flags) {
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> values = {
        {CLOSE_RANGE_UNSHARE, "CLOSE_RANGE_UNSHARE"},
        {CLOSE_RANGE_CLOEXEC, "CLOSE_RANGE_CLOEXEC"},
    };
    for (const auto& flag : values) {
        known |= flag.first;
    }
    return flag_list(flags, values, known);
}

std::string format_execveat_flags(std::uint64_t flags) {
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> values = {
#ifdef AT_EMPTY_PATH
        {AT_EMPTY_PATH, "AT_EMPTY_PATH"},
#endif
#ifdef AT_SYMLINK_NOFOLLOW
        {AT_SYMLINK_NOFOLLOW, "AT_SYMLINK_NOFOLLOW"},
#endif
    };
    for (const auto& flag : values) {
        known |= flag.first;
    }
    return flag_list(flags, values, known);
}

}  // namespace

bool decode_process_event(SyscallEvent& event, const TraceOptions& options) {
    const std::string& name = event.name;
    if (name == "execve") {
        event.decoded_args.push_back(
            read_remote_string_arg(event.tid, "pathname", event.raw_args[0], options.string_limit));
        add_arg(event, "argv",
                format_string_vector(event.tid, event.raw_args[1], options.string_limit),
                event.raw_args[1]);
        add_arg(event, "envp", format_hex(event.raw_args[2]), event.raw_args[2]);
        return true;
    }
    if (name == "execveat") {
        add_arg(event, "dirfd", format_dirfd(event.raw_args[0]), event.raw_args[0]);
        event.decoded_args.push_back(
            read_remote_string_arg(event.tid, "pathname", event.raw_args[1], options.string_limit));
        add_arg(event, "argv",
                format_string_vector(event.tid, event.raw_args[2], options.string_limit),
                event.raw_args[2]);
        add_arg(event, "envp", format_hex(event.raw_args[3]), event.raw_args[3]);
        add_arg(event, "flags", format_execveat_flags(event.raw_args[4]), event.raw_args[4]);
        return true;
    }
    if (name == "clone") {
        add_arg(event, "flags", format_clone_flags(event.raw_args[0]), event.raw_args[0]);
        add_arg(event, "child_stack",
                event.raw_args[1] == 0 ? "NULL" : format_hex(event.raw_args[1]), event.raw_args[1]);
        add_arg(event, "parent_tid",
                event.raw_args[2] == 0 ? "NULL" : format_hex(event.raw_args[2]), event.raw_args[2]);
        add_arg(event, "child_tid", event.raw_args[3] == 0 ? "NULL" : format_hex(event.raw_args[3]),
                event.raw_args[3]);
        add_arg(event, "tls", event.raw_args[4] == 0 ? "NULL" : format_hex(event.raw_args[4]),
                event.raw_args[4]);
        return true;
    }
    if (name == "clone3") {
        add_arg(event, "cl_args",
                format_clone3_args(event.tid, event.raw_args[0], event.raw_args[1]),
                event.raw_args[0]);
        add_arg(event, "size", std::to_string(event.raw_args[1]), event.raw_args[1]);
        return true;
    }
    if (name == "wait4") {
        add_arg(event, "pid", std::to_string(static_cast<int>(event.raw_args[0])),
                event.raw_args[0]);
        add_arg(
            event, "status",
            format_wait_status(event.tid, event.raw_args[1], !event.is_error && event.raw_ret > 0),
            event.raw_args[1]);
        add_arg(event, "options", format_wait_options(event.raw_args[2]), event.raw_args[2]);
        add_arg(event, "rusage", event.raw_args[3] == 0 ? "NULL" : format_hex(event.raw_args[3]),
                event.raw_args[3]);
        return true;
    }
    if (name == "prlimit64") {
        add_arg(event, "pid", std::to_string(static_cast<int>(event.raw_args[0])),
                event.raw_args[0]);
        add_arg(event, "resource", format_rlimit_resource(event.raw_args[1]), event.raw_args[1]);
        add_arg(event, "new_limit", format_rlimit(event.tid, event.raw_args[2]), event.raw_args[2]);
        add_arg(event, "old_limit",
                !event.is_error ? format_rlimit(event.tid, event.raw_args[3])
                                : (event.raw_args[3] == 0 ? "NULL" : format_hex(event.raw_args[3])),
                event.raw_args[3]);
        return true;
    }
    if (name == "statx") {
        add_arg(event, "dirfd", format_dirfd(event.raw_args[0]), event.raw_args[0]);
        event.decoded_args.push_back(
            read_remote_string_arg(event.tid, "pathname", event.raw_args[1], options.string_limit));
        add_arg(event, "flags", format_at_flags(event.raw_args[2]), event.raw_args[2]);
        add_arg(event, "mask", format_statx_mask(event.raw_args[3]), event.raw_args[3]);
        add_arg(event, "statxbuf", event.raw_args[4] == 0 ? "NULL" : format_hex(event.raw_args[4]),
                event.raw_args[4]);
        return true;
    }
    if (name == "newfstatat") {
        add_arg(event, "dirfd", format_dirfd(event.raw_args[0]), event.raw_args[0]);
        event.decoded_args.push_back(
            read_remote_string_arg(event.tid, "pathname", event.raw_args[1], options.string_limit));
        add_arg(event, "statbuf", event.raw_args[2] == 0 ? "NULL" : format_hex(event.raw_args[2]),
                event.raw_args[2]);
        add_arg(event, "flags", format_at_flags(event.raw_args[3]), event.raw_args[3]);
        return true;
    }
    if (name == "close_range") {
        add_arg(event, "first", std::to_string(event.raw_args[0]), event.raw_args[0]);
        add_arg(event, "last", std::to_string(event.raw_args[1]), event.raw_args[1]);
        add_arg(event, "flags", format_close_range_flags(event.raw_args[2]), event.raw_args[2]);
        return true;
    }
    if (name == "exit" || name == "exit_group") {
        add_arg(event, "status", std::to_string(event.raw_args[0]), event.raw_args[0]);
        return true;
    }
    return false;
}

void predecode_process_entry_event(SyscallEvent& event, const TraceOptions& options) {
    if (event.name != "execve" && event.name != "execveat") {
        return;
    }
    event.decoded_args.clear();
    (void)decode_process_event(event, options);
}

}  // namespace detail
}  // namespace mini_strace
