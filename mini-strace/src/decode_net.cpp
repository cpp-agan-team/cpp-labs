#include "decoder_internal.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <optional>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <utility>
#include <vector>

namespace mini_strace {
namespace detail {
namespace {

std::string format_fd(std::uint64_t value) {
    return std::to_string(static_cast<long long>(value));
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

std::string format_accept_flags(std::uint64_t flags) {
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> values = {
#ifdef SOCK_CLOEXEC
        {SOCK_CLOEXEC, "SOCK_CLOEXEC"},
#endif
#ifdef SOCK_NONBLOCK
        {SOCK_NONBLOCK, "SOCK_NONBLOCK"},
#endif
    };
    for (const auto& flag : values) {
        known |= flag.first;
    }
    return flag_list(flags, values, known);
}

std::string format_msg_flags(std::uint64_t flags) {
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> values = {
#ifdef MSG_OOB
        {MSG_OOB, "MSG_OOB"},
#endif
#ifdef MSG_PEEK
        {MSG_PEEK, "MSG_PEEK"},
#endif
#ifdef MSG_DONTROUTE
        {MSG_DONTROUTE, "MSG_DONTROUTE"},
#endif
#ifdef MSG_DONTWAIT
        {MSG_DONTWAIT, "MSG_DONTWAIT"},
#endif
#ifdef MSG_NOSIGNAL
        {MSG_NOSIGNAL, "MSG_NOSIGNAL"},
#endif
#ifdef MSG_WAITALL
        {MSG_WAITALL, "MSG_WAITALL"},
#endif
#ifdef MSG_CMSG_CLOEXEC
        {MSG_CMSG_CLOEXEC, "MSG_CMSG_CLOEXEC"},
#endif
    };
    for (const auto& flag : values) {
        known |= flag.first;
    }
    return flag_list(flags, values, known);
}

std::string format_sockopt_level(std::uint64_t level) {
    switch (static_cast<int>(level)) {
        case SOL_SOCKET:
            return "SOL_SOCKET";
        case IPPROTO_TCP:
            return "IPPROTO_TCP";
        default:
            return std::to_string(level);
    }
}

std::string format_sockopt_name(std::uint64_t level, std::uint64_t optname) {
    if (static_cast<int>(level) == SOL_SOCKET) {
        switch (static_cast<int>(optname)) {
#ifdef SO_REUSEADDR
            case SO_REUSEADDR:
                return "SO_REUSEADDR";
#endif
#ifdef SO_REUSEPORT
            case SO_REUSEPORT:
                return "SO_REUSEPORT";
#endif
#ifdef SO_KEEPALIVE
            case SO_KEEPALIVE:
                return "SO_KEEPALIVE";
#endif
#ifdef SO_RCVBUF
            case SO_RCVBUF:
                return "SO_RCVBUF";
#endif
#ifdef SO_SNDBUF
            case SO_SNDBUF:
                return "SO_SNDBUF";
#endif
#ifdef SO_RCVTIMEO
            case SO_RCVTIMEO:
                return "SO_RCVTIMEO";
#endif
#ifdef SO_SNDTIMEO
            case SO_SNDTIMEO:
                return "SO_SNDTIMEO";
#endif
            default:
                return std::to_string(optname);
        }
    }
    if (static_cast<int>(level) == IPPROTO_TCP) {
        switch (static_cast<int>(optname)) {
#ifdef TCP_NODELAY
            case TCP_NODELAY:
                return "TCP_NODELAY";
#endif
            default:
                return std::to_string(optname);
        }
    }
    return std::to_string(optname);
}

std::string format_sockopt_value(pid_t pid, std::uint64_t level, std::uint64_t optname,
                                 std::uint64_t optval, std::uint64_t optlen) {
    if (optval == 0) {
        return "NULL";
    }
    if (static_cast<int>(level) == SOL_SOCKET &&
        (static_cast<int>(optname) == SO_RCVTIMEO || static_cast<int>(optname) == SO_SNDTIMEO)) {
        const auto bytes =
            read_remote_bytes(pid, optval, std::min<std::uint64_t>(optlen, sizeof(timeval)));
        if (bytes.status == ArgReadStatus::Unreadable || bytes.data.size() < sizeof(timeval)) {
            return format_hex(optval);
        }
        timeval value{};
        std::memcpy(&value, bytes.data.data(), sizeof(value));
        std::ostringstream out;
        out << "{tv_sec=" << value.tv_sec << ", tv_usec=" << value.tv_usec << '}';
        return out.str();
    }
    if (optlen >= sizeof(int)) {
        const auto bytes = read_remote_bytes(pid, optval, sizeof(int));
        if (bytes.status != ArgReadStatus::Unreadable && bytes.data.size() >= sizeof(int)) {
            int value = 0;
            std::memcpy(&value, bytes.data.data(), sizeof(value));
            return std::to_string(value);
        }
    }
    return format_hex(optval);
}

std::string format_iovecs(pid_t pid, std::uint64_t address, std::uint64_t count, bool read_payload,
                          std::size_t string_limit) {
    constexpr std::uint64_t kMaxIovecs = 4;
    if (address == 0) {
        return "NULL";
    }
    if (count == 0) {
        return "[]";
    }
    const auto shown = static_cast<std::size_t>(std::min(count, kMaxIovecs));
    const auto bytes = read_remote_bytes(pid, address, shown * sizeof(iovec));
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.size() < sizeof(iovec)) {
        return format_hex(address);
    }

    std::ostringstream out;
    out << '[';
    const std::size_t entries = bytes.data.size() / sizeof(iovec);
    for (std::size_t i = 0; i < entries; ++i) {
        iovec iov{};
        std::memcpy(&iov, bytes.data.data() + i * sizeof(iov), sizeof(iov));
        if (i != 0) {
            out << ", ";
        }
        const auto base = reinterpret_cast<std::uint64_t>(iov.iov_base);
        out << "{base=";
        if (read_payload && i == 0 && iov.iov_base != nullptr && iov.iov_len > 0) {
            out << read_remote_buffer_arg(pid, "base", base, std::min(iov.iov_len, string_limit))
                       .value;
        } else {
            out << format_hex(base);
        }
        out << ", len=" << iov.iov_len << '}';
    }
    if (entries < static_cast<std::size_t>(count)) {
        if (entries != 0) {
            out << ", ";
        }
        out << "...";
    }
    out << ']';
    return out.str();
}

std::string format_msghdr(pid_t pid, std::uint64_t address, bool read_payload,
                          std::size_t string_limit) {
    if (address == 0) {
        return "NULL";
    }
    const auto bytes = read_remote_bytes(pid, address, sizeof(msghdr));
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.size() < sizeof(msghdr)) {
        return format_hex(address);
    }
    msghdr msg{};
    std::memcpy(&msg, bytes.data.data(), sizeof(msg));
    const auto name = reinterpret_cast<std::uint64_t>(msg.msg_name);
    const auto iov = reinterpret_cast<std::uint64_t>(msg.msg_iov);
    const auto control = reinterpret_cast<std::uint64_t>(msg.msg_control);

    std::ostringstream out;
    out << "{name=" << format_sockaddr(pid, name, msg.msg_namelen)
        << ", iov=" << format_iovecs(pid, iov, msg.msg_iovlen, read_payload, string_limit)
        << ", control=" << (control == 0 ? std::string("NULL") : format_hex(control))
        << ", controllen=" << msg.msg_controllen << '}';
    return out.str();
}

std::optional<std::uint64_t> read_socklen_value(pid_t pid, std::uint64_t address) {
    if (address == 0) {
        return std::nullopt;
    }
    const auto bytes = read_remote_bytes(pid, address, sizeof(socklen_t));
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.size() < sizeof(socklen_t)) {
        return std::nullopt;
    }
    socklen_t length = 0;
    std::memcpy(&length, bytes.data.data(), sizeof(length));
    return static_cast<std::uint64_t>(length);
}

std::string format_accept_addr(pid_t pid, std::uint64_t address, std::uint64_t length_address) {
    if (address == 0) {
        return "NULL";
    }
    const auto length = read_socklen_value(pid, length_address);
    if (!length) {
        return format_hex(address);
    }
    return format_sockaddr(pid, address, *length);
}

std::string format_accept_addrlen(pid_t pid, std::uint64_t address) {
    if (address == 0) {
        return "NULL";
    }
    const auto length = read_socklen_value(pid, address);
    if (!length) {
        return format_hex(address);
    }
    return std::to_string(*length);
}

}  // namespace

std::string format_sockaddr(pid_t pid, std::uint64_t address, std::uint64_t length) {
    if (address == 0 || length == 0) {
        return "NULL";
    }
    const std::size_t read_len =
        static_cast<std::size_t>(std::min<std::uint64_t>(length, sizeof(sockaddr_storage)));
    const auto bytes = read_remote_bytes(pid, address, read_len);
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.size() < sizeof(sa_family_t)) {
        return "<unreadable>";
    }

    const auto* sa = reinterpret_cast<const sockaddr*>(bytes.data.data());
    char buffer[INET6_ADDRSTRLEN]{};
    if (sa->sa_family == AF_INET && bytes.data.size() >= sizeof(sockaddr_in)) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(bytes.data.data());
        ::inet_ntop(AF_INET, &in->sin_addr, buffer, sizeof(buffer));
        return std::string("AF_INET ") + buffer + ":" + std::to_string(ntohs(in->sin_port));
    }
    if (sa->sa_family == AF_INET6 && bytes.data.size() >= sizeof(sockaddr_in6)) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(bytes.data.data());
        ::inet_ntop(AF_INET6, &in6->sin6_addr, buffer, sizeof(buffer));
        return std::string("AF_INET6 [") + buffer + "]:" + std::to_string(ntohs(in6->sin6_port));
    }
    if (sa->sa_family == AF_UNIX && bytes.data.size() >= sizeof(sockaddr_un)) {
        const auto* un = reinterpret_cast<const sockaddr_un*>(bytes.data.data());
        if (un->sun_path[0] == '\0') {
            return std::string("AF_UNIX @") +
                   escape_text(std::string(un->sun_path + 1,
                                           strnlen(un->sun_path + 1, sizeof(un->sun_path) - 1)));
        }
        return std::string("AF_UNIX ") +
               escape_text(std::string(un->sun_path, strnlen(un->sun_path, sizeof(un->sun_path))));
    }
    return "sa_family=" + std::to_string(sa->sa_family);
}

bool decode_net_event(SyscallEvent& event, const TraceOptions& options) {
    const std::string& name = event.name;
    if (name == "socket") {
        add_arg(event, "domain", format_socket_domain(event.raw_args[0]), event.raw_args[0]);
        add_arg(event, "type", format_socket_type(event.raw_args[1]), event.raw_args[1]);
        add_arg(event, "protocol", std::to_string(event.raw_args[2]), event.raw_args[2]);
        return true;
    }
    if (name == "connect" || name == "bind") {
        add_arg(event, "fd", format_fd(event.raw_args[0]), event.raw_args[0]);
        add_arg(event, "addr", format_sockaddr(event.tid, event.raw_args[1], event.raw_args[2]),
                event.raw_args[1]);
        add_arg(event, "addrlen", std::to_string(event.raw_args[2]), event.raw_args[2]);
        return true;
    }
    if (name == "listen") {
        add_arg(event, "fd", format_fd(event.raw_args[0]), event.raw_args[0]);
        add_arg(event, "backlog", std::to_string(static_cast<int>(event.raw_args[1])),
                event.raw_args[1]);
        return true;
    }
    if (name == "accept" || name == "accept4") {
        add_arg(event, "fd", format_fd(event.raw_args[0]), event.raw_args[0]);
        if (!event.is_error && event.raw_ret >= 0) {
            add_arg(event, "addr",
                    format_accept_addr(event.tid, event.raw_args[1], event.raw_args[2]),
                    event.raw_args[1]);
            add_arg(event, "addrlen", format_accept_addrlen(event.tid, event.raw_args[2]),
                    event.raw_args[2]);
        } else {
            add_arg(event, "addr", format_hex(event.raw_args[1]), event.raw_args[1]);
            add_arg(event, "addrlen", format_hex(event.raw_args[2]), event.raw_args[2]);
        }
        if (name == "accept4") {
            add_arg(event, "flags", format_accept_flags(event.raw_args[3]), event.raw_args[3]);
        }
        return true;
    }
    if (name == "sendto") {
        add_arg(event, "fd", format_fd(event.raw_args[0]), event.raw_args[0]);
        const auto bytes = static_cast<std::size_t>(
            std::min<std::uint64_t>(event.raw_args[2], options.string_limit));
        event.decoded_args.push_back(
            read_remote_buffer_arg(event.tid, "buf", event.raw_args[1], bytes));
        add_arg(event, "len", std::to_string(event.raw_args[2]), event.raw_args[2]);
        add_arg(event, "flags", format_msg_flags(event.raw_args[3]), event.raw_args[3]);
        add_arg(event, "addr", format_sockaddr(event.tid, event.raw_args[4], event.raw_args[5]),
                event.raw_args[4]);
        add_arg(event, "addrlen", std::to_string(event.raw_args[5]), event.raw_args[5]);
        return true;
    }
    if (name == "recvfrom") {
        add_arg(event, "fd", format_fd(event.raw_args[0]), event.raw_args[0]);
        if (!event.is_error && event.raw_ret > 0) {
            const auto bytes = static_cast<std::size_t>(std::min<std::int64_t>(
                event.raw_ret, static_cast<std::int64_t>(options.string_limit)));
            event.decoded_args.push_back(
                read_remote_buffer_arg(event.tid, "buf", event.raw_args[1], bytes));
        } else {
            add_arg(event, "buf", format_hex(event.raw_args[1]), event.raw_args[1]);
        }
        add_arg(event, "len", std::to_string(event.raw_args[2]), event.raw_args[2]);
        add_arg(event, "flags", format_msg_flags(event.raw_args[3]), event.raw_args[3]);
        if (!event.is_error && event.raw_ret >= 0) {
            add_arg(event, "addr",
                    format_accept_addr(event.tid, event.raw_args[4], event.raw_args[5]),
                    event.raw_args[4]);
            add_arg(event, "addrlen", format_accept_addrlen(event.tid, event.raw_args[5]),
                    event.raw_args[5]);
        } else {
            add_arg(event, "addr", event.raw_args[4] == 0 ? "NULL" : format_hex(event.raw_args[4]),
                    event.raw_args[4]);
            add_arg(event, "addrlen",
                    event.raw_args[5] == 0 ? "NULL" : format_hex(event.raw_args[5]),
                    event.raw_args[5]);
        }
        return true;
    }
    if (name == "sendmsg" || name == "recvmsg") {
        add_arg(event, "fd", format_fd(event.raw_args[0]), event.raw_args[0]);
        const bool read_payload = name == "sendmsg" || (!event.is_error && event.raw_ret > 0);
        add_arg(event, "msg",
                format_msghdr(event.tid, event.raw_args[1], read_payload, options.string_limit),
                event.raw_args[1]);
        add_arg(event, "flags", format_msg_flags(event.raw_args[2]), event.raw_args[2]);
        return true;
    }
    if (name == "setsockopt" || name == "getsockopt") {
        add_arg(event, "fd", format_fd(event.raw_args[0]), event.raw_args[0]);
        add_arg(event, "level", format_sockopt_level(event.raw_args[1]), event.raw_args[1]);
        add_arg(event, "optname", format_sockopt_name(event.raw_args[1], event.raw_args[2]),
                event.raw_args[2]);
        add_arg(event, "optval",
                format_sockopt_value(event.tid, event.raw_args[1], event.raw_args[2],
                                     event.raw_args[3], event.raw_args[4]),
                event.raw_args[3]);
        add_arg(event, "optlen", std::to_string(event.raw_args[4]), event.raw_args[4]);
        return true;
    }
    return false;
}

}  // namespace detail
}  // namespace mini_strace
