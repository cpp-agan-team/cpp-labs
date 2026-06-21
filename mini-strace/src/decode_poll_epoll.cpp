#include "decoder_internal.hpp"

#include <algorithm>
#include <cstring>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/epoll.h>
#include <time.h>
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

std::string format_poll_events(short events) {
    const auto value = static_cast<std::uint64_t>(static_cast<unsigned short>(events));
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> values = {
#ifdef POLLIN
        {POLLIN, "POLLIN"},
#endif
#ifdef POLLPRI
        {POLLPRI, "POLLPRI"},
#endif
#ifdef POLLOUT
        {POLLOUT, "POLLOUT"},
#endif
#ifdef POLLERR
        {POLLERR, "POLLERR"},
#endif
#ifdef POLLHUP
        {POLLHUP, "POLLHUP"},
#endif
#ifdef POLLNVAL
        {POLLNVAL, "POLLNVAL"},
#endif
#ifdef POLLRDHUP
        {POLLRDHUP, "POLLRDHUP"},
#endif
    };
    for (const auto& flag : values) {
        known |= flag.first;
    }
    return flag_list(value, values, known);
}

std::string format_pollfds(pid_t pid, std::uint64_t address, std::uint64_t nfds) {
    constexpr std::uint64_t kMaxPollFds = 4;
    if (address == 0) {
        return "NULL";
    }
    if (nfds == 0) {
        return "[]";
    }
    const auto shown = static_cast<std::size_t>(std::min(nfds, kMaxPollFds));
    const auto bytes = read_remote_bytes(pid, address, shown * sizeof(pollfd));
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.size() < sizeof(pollfd)) {
        return format_hex(address);
    }

    std::ostringstream out;
    out << '[';
    const std::size_t entries = bytes.data.size() / sizeof(pollfd);
    for (std::size_t i = 0; i < entries; ++i) {
        pollfd fd{};
        std::memcpy(&fd, bytes.data.data() + i * sizeof(fd), sizeof(fd));
        if (i != 0) {
            out << ", ";
        }
        out << "{fd=" << fd.fd << ", events=" << format_poll_events(fd.events)
            << ", revents=" << format_poll_events(fd.revents) << '}';
    }
    if (entries < static_cast<std::size_t>(nfds)) {
        if (entries != 0) {
            out << ", ";
        }
        out << "...";
    }
    out << ']';
    return out.str();
}

std::string format_timespec(pid_t pid, std::uint64_t address) {
    if (address == 0) {
        return "NULL";
    }
    const auto bytes = read_remote_bytes(pid, address, sizeof(timespec));
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.size() < sizeof(timespec)) {
        return format_hex(address);
    }
    timespec value{};
    std::memcpy(&value, bytes.data.data(), sizeof(value));
    std::ostringstream out;
    out << "{tv_sec=" << value.tv_sec << ", tv_nsec=" << value.tv_nsec << '}';
    return out.str();
}

std::string format_epoll_create_flags(std::uint64_t flags) {
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> values = {
#ifdef EPOLL_CLOEXEC
        {EPOLL_CLOEXEC, "EPOLL_CLOEXEC"},
#endif
    };
    for (const auto& flag : values) {
        known |= flag.first;
    }
    return flag_list(flags, values, known);
}

std::string format_epoll_ctl_op(std::uint64_t op) {
    switch (static_cast<int>(op)) {
        case EPOLL_CTL_ADD:
            return "EPOLL_CTL_ADD";
        case EPOLL_CTL_DEL:
            return "EPOLL_CTL_DEL";
        case EPOLL_CTL_MOD:
            return "EPOLL_CTL_MOD";
        default:
            return std::to_string(op);
    }
}

std::string format_epoll_events(std::uint64_t events) {
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> values = {
#ifdef EPOLLIN
        {EPOLLIN, "EPOLLIN"},
#endif
#ifdef EPOLLOUT
        {EPOLLOUT, "EPOLLOUT"},
#endif
#ifdef EPOLLERR
        {EPOLLERR, "EPOLLERR"},
#endif
#ifdef EPOLLHUP
        {EPOLLHUP, "EPOLLHUP"},
#endif
#ifdef EPOLLRDHUP
        {EPOLLRDHUP, "EPOLLRDHUP"},
#endif
#ifdef EPOLLPRI
        {EPOLLPRI, "EPOLLPRI"},
#endif
#ifdef EPOLLET
        {EPOLLET, "EPOLLET"},
#endif
#ifdef EPOLLONESHOT
        {EPOLLONESHOT, "EPOLLONESHOT"},
#endif
#ifdef EPOLLEXCLUSIVE
        {EPOLLEXCLUSIVE, "EPOLLEXCLUSIVE"},
#endif
    };
    for (const auto& flag : values) {
        known |= flag.first;
    }
    return flag_list(events, values, known);
}

std::string format_epoll_event(pid_t pid, std::uint64_t address) {
    if (address == 0) {
        return "NULL";
    }
    const auto bytes = read_remote_bytes(pid, address, sizeof(epoll_event));
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.size() < sizeof(epoll_event)) {
        return format_hex(address);
    }
    epoll_event event{};
    std::memcpy(&event, bytes.data.data(), sizeof(event));
    std::ostringstream out;
    out << "{events=" << format_epoll_events(event.events) << ", data_fd=" << event.data.fd
        << ", data_u64=" << format_hex(event.data.u64) << '}';
    return out.str();
}

}  // namespace

bool decode_poll_epoll_event(SyscallEvent& event) {
    const std::string& name = event.name;
    if (name == "poll") {
        add_arg(event, "fds", format_pollfds(event.tid, event.raw_args[0], event.raw_args[1]),
                event.raw_args[0]);
        add_arg(event, "nfds", std::to_string(event.raw_args[1]), event.raw_args[1]);
        add_arg(event, "timeout", std::to_string(static_cast<int>(event.raw_args[2])),
                event.raw_args[2]);
        return true;
    }
    if (name == "ppoll") {
        add_arg(event, "fds", format_pollfds(event.tid, event.raw_args[0], event.raw_args[1]),
                event.raw_args[0]);
        add_arg(event, "nfds", std::to_string(event.raw_args[1]), event.raw_args[1]);
        add_arg(event, "timeout", format_timespec(event.tid, event.raw_args[2]), event.raw_args[2]);
        add_arg(event, "sigmask", event.raw_args[3] == 0 ? "NULL" : format_hex(event.raw_args[3]),
                event.raw_args[3]);
        add_arg(event, "sigsetsize", std::to_string(event.raw_args[4]), event.raw_args[4]);
        return true;
    }
    if (name == "epoll_create") {
        add_arg(event, "size", std::to_string(event.raw_args[0]), event.raw_args[0]);
        return true;
    }
    if (name == "epoll_create1") {
        add_arg(event, "flags", format_epoll_create_flags(event.raw_args[0]), event.raw_args[0]);
        return true;
    }
    if (name == "epoll_ctl") {
        add_arg(event, "epfd", format_fd(event.raw_args[0]), event.raw_args[0]);
        add_arg(event, "op", format_epoll_ctl_op(event.raw_args[1]), event.raw_args[1]);
        add_arg(event, "fd", format_fd(event.raw_args[2]), event.raw_args[2]);
        add_arg(event, "event", format_epoll_event(event.tid, event.raw_args[3]),
                event.raw_args[3]);
        return true;
    }
    if (name == "epoll_wait" || name == "epoll_pwait") {
        add_arg(event, "epfd", format_fd(event.raw_args[0]), event.raw_args[0]);
        add_arg(event, "events", event.raw_args[1] == 0 ? "NULL" : format_hex(event.raw_args[1]),
                event.raw_args[1]);
        add_arg(event, "maxevents", std::to_string(event.raw_args[2]), event.raw_args[2]);
        add_arg(event, "timeout", std::to_string(static_cast<long long>(event.raw_args[3])),
                event.raw_args[3]);
        if (name == "epoll_pwait") {
            add_arg(event, "sigmask",
                    event.raw_args[4] == 0 ? "NULL" : format_hex(event.raw_args[4]),
                    event.raw_args[4]);
            add_arg(event, "sigsetsize", std::to_string(event.raw_args[5]), event.raw_args[5]);
        }
        return true;
    }
    return false;
}

}  // namespace detail
}  // namespace mini_strace
