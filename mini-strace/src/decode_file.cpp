#include "decoder_internal.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <linux/openat2.h>
#include <optional>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>
#include <vector>

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

std::string format_socket_domain(std::uint64_t domain) {
    switch (static_cast<int>(domain)) {
        case AF_INET:
            return "AF_INET";
        case AF_INET6:
            return "AF_INET6";
        case AF_UNIX:
            return "AF_UNIX";
        case AF_NETLINK:
            return "AF_NETLINK";
        default:
            return std::to_string(domain);
    }
}

std::string format_socket_type(std::uint64_t type) {
    const int base = static_cast<int>(type) & 0xf;
    std::string result;
    switch (base) {
        case SOCK_STREAM:
            result = "SOCK_STREAM";
            break;
        case SOCK_DGRAM:
            result = "SOCK_DGRAM";
            break;
        case SOCK_RAW:
            result = "SOCK_RAW";
            break;
        case SOCK_SEQPACKET:
            result = "SOCK_SEQPACKET";
            break;
        default:
            result = std::to_string(type);
            break;
    }
#ifdef SOCK_NONBLOCK
    if ((static_cast<int>(type) & SOCK_NONBLOCK) != 0) {
        result += "|SOCK_NONBLOCK";
    }
#endif
#ifdef SOCK_CLOEXEC
    if ((static_cast<int>(type) & SOCK_CLOEXEC) != 0) {
        result += "|SOCK_CLOEXEC";
    }
#endif
    return result;
}

std::string format_pipe_flags(std::uint64_t flags) {
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> values = {
#ifdef O_CLOEXEC
        {O_CLOEXEC, "O_CLOEXEC"},
#endif
#ifdef O_NONBLOCK
        {O_NONBLOCK, "O_NONBLOCK"},
#endif
    };
    for (const auto& flag : values) {
        known |= flag.first;
    }
    return flag_list(flags, values, known);
}

std::string format_lseek_whence(std::uint64_t whence) {
    switch (static_cast<int>(whence)) {
        case SEEK_SET:
            return "SEEK_SET";
        case SEEK_CUR:
            return "SEEK_CUR";
        case SEEK_END:
            return "SEEK_END";
#ifdef SEEK_DATA
        case SEEK_DATA:
            return "SEEK_DATA";
#endif
#ifdef SEEK_HOLE
        case SEEK_HOLE:
            return "SEEK_HOLE";
#endif
        default:
            return std::to_string(whence);
    }
}

std::string format_openat2_resolve(std::uint64_t flags) {
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> values = {
#ifdef RESOLVE_NO_XDEV
        {RESOLVE_NO_XDEV, "RESOLVE_NO_XDEV"},
#endif
#ifdef RESOLVE_NO_MAGICLINKS
        {RESOLVE_NO_MAGICLINKS, "RESOLVE_NO_MAGICLINKS"},
#endif
#ifdef RESOLVE_NO_SYMLINKS
        {RESOLVE_NO_SYMLINKS, "RESOLVE_NO_SYMLINKS"},
#endif
#ifdef RESOLVE_BENEATH
        {RESOLVE_BENEATH, "RESOLVE_BENEATH"},
#endif
#ifdef RESOLVE_IN_ROOT
        {RESOLVE_IN_ROOT, "RESOLVE_IN_ROOT"},
#endif
#ifdef RESOLVE_CACHED
        {RESOLVE_CACHED, "RESOLVE_CACHED"},
#endif
    };
    for (const auto& flag : values) {
        known |= flag.first;
    }
    return flag_list(flags, values, known);
}

std::string format_open_how(pid_t pid, std::uint64_t address, std::uint64_t size) {
    if (address == 0) {
        return "NULL";
    }
    if (size == 0) {
        return format_hex(address);
    }
    const std::size_t read_len =
        static_cast<std::size_t>(std::min<std::uint64_t>(size, sizeof(open_how)));
    const auto bytes = read_remote_bytes(pid, address, read_len);
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.empty()) {
        return "<unreadable>";
    }

    open_how how{};
    std::memcpy(&how, bytes.data.data(), std::min(bytes.data.size(), sizeof(how)));
    std::ostringstream out;
    out << "{flags=" << format_open_flags(how.flags) << ", mode=0" << std::oct
        << (how.mode & 07777U) << std::dec << ", resolve=" << format_openat2_resolve(how.resolve);
    if (size > sizeof(open_how)) {
        out << ", size=" << size;
    }
    out << '}';
    return out.str();
}

std::optional<std::array<int, 2>> read_fd_pair(pid_t pid, std::uint64_t address) {
    const auto bytes = read_remote_bytes(pid, address, sizeof(int) * 2);
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.size() < sizeof(int) * 2) {
        return std::nullopt;
    }
    std::array<int, 2> fds{};
    std::memcpy(fds.data(), bytes.data.data(), sizeof(int) * 2);
    return fds;
}

std::string format_fd_pair(pid_t pid, std::uint64_t address) {
    if (address == 0) {
        return "NULL";
    }
    const auto fds = read_fd_pair(pid, address);
    if (!fds) {
        return format_hex(address);
    }
    return "[" + std::to_string((*fds)[0]) + "," + std::to_string((*fds)[1]) + "]";
}

std::string format_fcntl_cmd(std::uint64_t command) {
    switch (static_cast<int>(command)) {
#ifdef F_DUPFD
        case F_DUPFD:
            return "F_DUPFD";
#endif
#ifdef F_GETFD
        case F_GETFD:
            return "F_GETFD";
#endif
#ifdef F_SETFD
        case F_SETFD:
            return "F_SETFD";
#endif
#ifdef F_GETFL
        case F_GETFL:
            return "F_GETFL";
#endif
#ifdef F_SETFL
        case F_SETFL:
            return "F_SETFL";
#endif
#ifdef F_DUPFD_CLOEXEC
        case F_DUPFD_CLOEXEC:
            return "F_DUPFD_CLOEXEC";
#endif
        default:
            return std::to_string(command);
    }
}

std::string format_fd_flags(std::uint64_t flags) {
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> values = {
#ifdef FD_CLOEXEC
        {FD_CLOEXEC, "FD_CLOEXEC"},
#endif
    };
    for (const auto& flag : values) {
        known |= flag.first;
    }
    return flag_list(flags, values, known);
}

std::string format_fcntl_arg(std::uint64_t command, std::uint64_t arg) {
    switch (static_cast<int>(command)) {
#ifdef F_SETFD
        case F_SETFD:
            return format_fd_flags(arg);
#endif
#ifdef F_SETFL
        case F_SETFL:
            return format_open_flags(arg);
#endif
        default:
            return std::to_string(static_cast<long long>(arg));
    }
}

void decode_open_like(SyscallEvent& event, const TraceOptions& options, bool has_dirfd) {
    std::size_t path_index = has_dirfd ? 1 : 0;
    std::size_t flags_index = has_dirfd ? 2 : 1;
    if (has_dirfd) {
        add_arg(event, "dirfd", format_dirfd(event.raw_args[0]), event.raw_args[0]);
    }
    event.decoded_args.push_back(read_remote_string_arg(
        event.tid, "pathname", event.raw_args[path_index], options.string_limit));
    add_arg(event, "flags", format_open_flags(event.raw_args[flags_index]),
            event.raw_args[flags_index]);
    add_arg(event, "mode", "0" + std::to_string(event.raw_args[flags_index + 1] & 07777U),
            event.raw_args[flags_index + 1]);
}

}  // namespace

std::string format_open_flags(std::uint64_t flags) {
    std::vector<std::string> parts;
    switch (flags & O_ACCMODE) {
        case O_RDONLY:
            parts.emplace_back("O_RDONLY");
            break;
        case O_WRONLY:
            parts.emplace_back("O_WRONLY");
            break;
        case O_RDWR:
            parts.emplace_back("O_RDWR");
            break;
        default:
            break;
    }

    std::uint64_t known = O_ACCMODE;
    const std::vector<std::pair<std::uint64_t, const char*>> extra = {
#ifdef O_CREAT
        {O_CREAT, "O_CREAT"},
#endif
#ifdef O_EXCL
        {O_EXCL, "O_EXCL"},
#endif
#ifdef O_NOCTTY
        {O_NOCTTY, "O_NOCTTY"},
#endif
#ifdef O_TRUNC
        {O_TRUNC, "O_TRUNC"},
#endif
#ifdef O_APPEND
        {O_APPEND, "O_APPEND"},
#endif
#ifdef O_NONBLOCK
        {O_NONBLOCK, "O_NONBLOCK"},
#endif
#ifdef O_DIRECTORY
        {O_DIRECTORY, "O_DIRECTORY"},
#endif
#ifdef O_NOFOLLOW
        {O_NOFOLLOW, "O_NOFOLLOW"},
#endif
#ifdef O_CLOEXEC
        {O_CLOEXEC, "O_CLOEXEC"},
#endif
    };
    for (const auto& item : extra) {
        known |= item.first;
        if ((flags & item.first) != 0) {
            parts.emplace_back(item.second);
        }
    }
    const std::uint64_t unknown = flags & ~known;
    if (unknown != 0) {
        parts.push_back(format_hex(unknown));
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

bool decode_file_event(SyscallEvent& event, const TraceOptions& options) {
    const std::string& name = event.name;
    if (name == "read") {
        add_arg(event, "fd", format_fd(event.raw_args[0]), event.raw_args[0]);
        if (!event.is_error && event.raw_ret > 0) {
            const auto bytes = static_cast<std::size_t>(std::min<std::int64_t>(
                event.raw_ret, static_cast<std::int64_t>(options.string_limit)));
            event.decoded_args.push_back(
                read_remote_buffer_arg(event.tid, "buf", event.raw_args[1], bytes));
        } else {
            add_arg(event, "buf", format_hex(event.raw_args[1]), event.raw_args[1]);
        }
        add_arg(event, "count", std::to_string(event.raw_args[2]), event.raw_args[2]);
        return true;
    }
    if (name == "write") {
        add_arg(event, "fd", format_fd(event.raw_args[0]), event.raw_args[0]);
        const auto bytes = static_cast<std::size_t>(
            std::min<std::uint64_t>(event.raw_args[2], options.string_limit));
        event.decoded_args.push_back(
            read_remote_buffer_arg(event.tid, "buf", event.raw_args[1], bytes));
        add_arg(event, "count", std::to_string(event.raw_args[2]), event.raw_args[2]);
        return true;
    }
    if (name == "openat") {
        decode_open_like(event, options, true);
        return true;
    }
    if (name == "openat2") {
        add_arg(event, "dirfd", format_dirfd(event.raw_args[0]), event.raw_args[0]);
        event.decoded_args.push_back(
            read_remote_string_arg(event.tid, "pathname", event.raw_args[1], options.string_limit));
        add_arg(event, "how", format_open_how(event.tid, event.raw_args[2], event.raw_args[3]),
                event.raw_args[2]);
        add_arg(event, "size", std::to_string(event.raw_args[3]), event.raw_args[3]);
        return true;
    }
    if (name == "open" || name == "creat") {
        decode_open_like(event, options, false);
        return true;
    }
    if (name == "close") {
        add_arg(event, "fd", format_fd(event.raw_args[0]), event.raw_args[0]);
        return true;
    }
    if (name == "lseek") {
        add_arg(event, "fd", format_fd(event.raw_args[0]), event.raw_args[0]);
        add_arg(event, "offset", std::to_string(static_cast<long long>(event.raw_args[1])),
                event.raw_args[1]);
        add_arg(event, "whence", format_lseek_whence(event.raw_args[2]), event.raw_args[2]);
        return true;
    }
    if (name == "socketpair") {
        add_arg(event, "domain", format_socket_domain(event.raw_args[0]), event.raw_args[0]);
        add_arg(event, "type", format_socket_type(event.raw_args[1]), event.raw_args[1]);
        add_arg(event, "protocol", std::to_string(event.raw_args[2]), event.raw_args[2]);
        if (!event.is_error && event.raw_ret == 0) {
            add_arg(event, "sv", format_fd_pair(event.tid, event.raw_args[3]), event.raw_args[3]);
        } else {
            add_arg(event, "sv", event.raw_args[3] == 0 ? "NULL" : format_hex(event.raw_args[3]),
                    event.raw_args[3]);
        }
        return true;
    }
    if (name == "dup" || name == "dup2" || name == "dup3") {
        add_arg(event, "oldfd", format_fd(event.raw_args[0]), event.raw_args[0]);
        if (name != "dup") {
            add_arg(event, "newfd", format_fd(event.raw_args[1]), event.raw_args[1]);
        }
        return true;
    }
    if (name == "pipe" || name == "pipe2") {
        if (!event.is_error && event.raw_ret == 0) {
            add_arg(event, "pipefd", format_fd_pair(event.tid, event.raw_args[0]),
                    event.raw_args[0]);
        } else {
            add_arg(event, "pipefd",
                    event.raw_args[0] == 0 ? "NULL" : format_hex(event.raw_args[0]),
                    event.raw_args[0]);
        }
        if (name == "pipe2") {
            add_arg(event, "flags", format_pipe_flags(event.raw_args[1]), event.raw_args[1]);
        }
        return true;
    }
    if (name == "fcntl") {
        add_arg(event, "fd", format_fd(event.raw_args[0]), event.raw_args[0]);
        add_arg(event, "cmd", format_fcntl_cmd(event.raw_args[1]), event.raw_args[1]);
        add_arg(event, "arg", format_fcntl_arg(event.raw_args[1], event.raw_args[2]),
                event.raw_args[2]);
        return true;
    }
    return false;
}

}  // namespace detail
}  // namespace mini_strace
