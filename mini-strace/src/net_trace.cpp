#include "internal.hpp"

#include <algorithm>
#include <ostream>
#include <string>

namespace mini_strace {
namespace detail {
namespace {

bool is_network_syscall(const std::string& name) {
    return name == "socket" || name == "bind" || name == "listen" || name == "connect" ||
           name == "accept" || name == "accept4" || name == "sendto" || name == "recvfrom" ||
           name == "sendmsg" || name == "recvmsg" || name == "setsockopt" || name == "getsockopt";
}

std::string arg_value(const SyscallEvent& event, const std::string& name) {
    for (const auto& arg : event.decoded_args) {
        if (arg.name == name) {
            return arg.value;
        }
    }
    return "";
}

int first_fd(const SyscallEvent& event) {
    return static_cast<int>(event.raw_args[0]);
}

SocketSummary& socket_for(std::map<std::pair<pid_t, int>, SocketSummary>& sockets, pid_t pid,
                          int fd) {
    auto& socket = sockets[{pid, fd}];
    socket.pid = pid;
    socket.fd = fd;
    return socket;
}

void remember_option(SocketSummary& socket, const std::string& option) {
    if (option.empty() ||
        std::find(socket.options.begin(), socket.options.end(), option) != socket.options.end()) {
        return;
    }
    socket.options.push_back(option);
}

std::string join_options(const std::vector<std::string>& options) {
    std::string out;
    for (std::size_t i = 0; i < options.size(); ++i) {
        if (i != 0) {
            out += ",";
        }
        out += options[i];
    }
    return out;
}

void observe_syscall_stats(std::map<std::string, NetworkSyscallStats>& syscalls,
                           const SyscallEvent& event) {
    auto& stats = syscalls[event.name];
    ++stats.count;
    if (event.is_error) {
        ++stats.errors;
    }
    stats.total_ns += event.duration_ns;
    stats.max_ns = std::max(stats.max_ns, event.duration_ns);
}

}  // namespace

void NetworkSummary::observe(const SyscallEvent& event) {
    if (!is_network_syscall(event.name)) {
        return;
    }
    observe_syscall_stats(syscalls_, event);
    const std::string& name = event.name;
    if (name == "socket" && !event.is_error && event.raw_ret >= 0) {
        auto& socket = socket_for(sockets_, event.pid, static_cast<int>(event.raw_ret));
        socket.domain = arg_value(event, "domain");
        socket.type = arg_value(event, "type");
        socket.protocol = arg_value(event, "protocol");
        return;
    }
    if (name == "bind" && !event.is_error) {
        auto& socket = socket_for(sockets_, event.pid, first_fd(event));
        socket.local = arg_value(event, "addr");
        return;
    }
    if (name == "connect" && !event.is_error) {
        auto& socket = socket_for(sockets_, event.pid, first_fd(event));
        socket.peer = arg_value(event, "addr");
        return;
    }
    if ((name == "accept" || name == "accept4") && !event.is_error && event.raw_ret >= 0) {
        auto& socket = socket_for(sockets_, event.pid, static_cast<int>(event.raw_ret));
        socket.peer = arg_value(event, "addr");
        return;
    }
    if (name == "setsockopt" || name == "getsockopt") {
        auto& socket = socket_for(sockets_, event.pid, first_fd(event));
        if (event.is_error) {
            ++socket.errors;
        }
        remember_option(socket, arg_value(event, "optname"));
        return;
    }
    if (name == "sendto" || name == "sendmsg") {
        auto& socket = socket_for(sockets_, event.pid, first_fd(event));
        if (event.is_error) {
            ++socket.errors;
            return;
        }
        ++socket.send_calls;
        if (event.raw_ret > 0) {
            socket.sent_bytes += static_cast<std::uint64_t>(event.raw_ret);
        }
        if (name == "sendto") {
            const auto peer = arg_value(event, "addr");
            if (!peer.empty() && peer != "NULL") {
                socket.peer = peer;
            }
        }
        return;
    }
    if (name == "recvfrom" || name == "recvmsg") {
        auto& socket = socket_for(sockets_, event.pid, first_fd(event));
        if (event.is_error) {
            ++socket.errors;
            return;
        }
        ++socket.recv_calls;
        if (event.raw_ret > 0) {
            socket.recv_bytes += static_cast<std::uint64_t>(event.raw_ret);
        }
        if (name == "recvfrom") {
            const auto peer = arg_value(event, "addr");
            if (!peer.empty() && peer != "NULL") {
                socket.peer = peer;
            }
        }
    }
}

void NetworkSummary::write(std::ostream& out) const {
    out << "network:\n";
    if (syscalls_.empty()) {
        out << "  no_network_events\n";
        return;
    }
    if (!sockets_.empty()) {
        out << "  sockets:\n";
        for (const auto& item : sockets_) {
            const auto& socket = item.second;
            out << "    pid=" << socket.pid << " fd=" << socket.fd;
            if (!socket.domain.empty()) {
                out << " domain=" << socket.domain;
            }
            if (!socket.type.empty()) {
                out << " type=" << socket.type;
            }
            if (!socket.local.empty()) {
                out << " local=" << socket.local;
            }
            if (!socket.peer.empty()) {
                out << " peer=" << socket.peer;
            }
            out << " sent=" << socket.sent_bytes << " recv=" << socket.recv_bytes
                << " send_calls=" << socket.send_calls << " recv_calls=" << socket.recv_calls
                << " errors=" << socket.errors;
            if (!socket.options.empty()) {
                out << " options=" << join_options(socket.options);
            }
            out << '\n';
        }
    }
    out << "  syscalls:\n";
    for (const auto& item : syscalls_) {
        out << "    " << item.first << ": calls=" << item.second.count
            << " errors=" << item.second.errors
            << " total_us=" << (static_cast<double>(item.second.total_ns) / 1000.0)
            << " max_us=" << (static_cast<double>(item.second.max_ns) / 1000.0) << '\n';
    }
}

}  // namespace detail
}  // namespace mini_strace
