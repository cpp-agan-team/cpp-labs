#include "fd_inspector_internal.hpp"
#include "unique_fd.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cstddef>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>
#include <map>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fdi::detail {
namespace {

std::string endpoint_to_string(const sockaddr_storage& storage) {
    char addr[INET6_ADDRSTRLEN] = {};
    uint16_t port = 0;

    if (storage.ss_family == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(&storage);
        if (!::inet_ntop(AF_INET, &in->sin_addr, addr, sizeof(addr))) {
            return {};
        }
        port = ntohs(in->sin_port);
    } else if (storage.ss_family == AF_INET6) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(&storage);
        if (!::inet_ntop(AF_INET6, &in6->sin6_addr, addr, sizeof(addr))) {
            return {};
        }
        port = ntohs(in6->sin6_port);
    } else {
        return {};
    }

    std::ostringstream out;
    out << addr << ':' << port;
    return out.str();
}

std::string inet_diag_endpoint(int family, const uint32_t* addr_words, uint16_t be_port) {
    char addr[INET6_ADDRSTRLEN] = {};
    if (family == AF_INET) {
        in_addr in{};
        in.s_addr = addr_words[0];
        if (!::inet_ntop(AF_INET, &in, addr, sizeof(addr))) {
            return {};
        }
    } else if (family == AF_INET6) {
        in6_addr in6{};
        std::memcpy(&in6, addr_words, sizeof(in6));
        if (!::inet_ntop(AF_INET6, &in6, addr, sizeof(addr))) {
            return {};
        }
    } else {
        return {};
    }

    std::ostringstream out;
    out << addr << ':' << ntohs(be_port);
    return out.str();
}

std::string tcp_state_name(uint8_t state) {
    switch (state) {
        case 1:
            return "ESTABLISHED";
        case 2:
            return "SYN_SENT";
        case 3:
            return "SYN_RECV";
        case 4:
            return "FIN_WAIT1";
        case 5:
            return "FIN_WAIT2";
        case 6:
            return "TIME_WAIT";
        case 7:
            return "CLOSE";
        case 8:
            return "CLOSE_WAIT";
        case 9:
            return "LAST_ACK";
        case 10:
            return "LISTEN";
        case 11:
            return "CLOSING";
        default:
            return "UNKNOWN";
    }
}

template <class T>
bool get_socket_option(int fd, int level, int optname, T* value) {
    socklen_t len = sizeof(T);
    return ::getsockopt(fd, level, optname, value, &len) == 0;
}

template <class T>
std::optional<T> attr_value(const rtattr* attr) {
    if (RTA_PAYLOAD(attr) < static_cast<int>(sizeof(T))) {
        return std::nullopt;
    }
    T value{};
    std::memcpy(&value, RTA_DATA(attr), sizeof(T));
    return value;
}

std::string attr_string(const rtattr* attr) {
    int payload = RTA_PAYLOAD(attr);
    if (payload <= 0) {
        return {};
    }
    const char* data = static_cast<const char*>(RTA_DATA(attr));
    size_t length = static_cast<size_t>(payload);
    if (length > 0 && data[length - 1] == '\0') {
        --length;
    }
    if (length > 0 && data[0] == '\0') {
        return "@" + std::string(data + 1, length - 1);
    }
    return std::string(data, length);
}

void parse_inet_diag_attrs(const inet_diag_msg& msg, int attr_len, SocketInfo* info) {
    auto* attr = reinterpret_cast<rtattr*>(
        const_cast<char*>(reinterpret_cast<const char*>(&msg) + sizeof(inet_diag_msg)));
    for (; RTA_OK(attr, attr_len); attr = RTA_NEXT(attr, attr_len)) {
        switch (attr->rta_type) {
            case INET_DIAG_INFO: {
                constexpr size_t kRequiredSize =
                    offsetof(tcp_info, tcpi_snd_cwnd) + sizeof(uint32_t);
                if (RTA_PAYLOAD(attr) >= static_cast<int>(kRequiredSize)) {
                    tcp_info tcp{};
                    std::memcpy(&tcp, RTA_DATA(attr),
                                std::min(sizeof(tcp), static_cast<size_t>(RTA_PAYLOAD(attr))));
                    info->has_tcp_info = true;
                    info->state = tcp_state_name(tcp.tcpi_state);
                    info->rtt_us = tcp.tcpi_rtt;
                    info->snd_cwnd = tcp.tcpi_snd_cwnd;
                    info->retrans = tcp.tcpi_retrans;
                }
                break;
            }
            case INET_DIAG_MEMINFO: {
                auto mem = attr_value<inet_diag_meminfo>(attr);
                if (mem) {
                    info->rmem = mem->idiag_rmem;
                    info->wmem = mem->idiag_wmem;
                }
                break;
            }
            case INET_DIAG_SKMEMINFO: {
                if (RTA_PAYLOAD(attr) >= static_cast<int>(sizeof(uint32_t) * SK_MEMINFO_VARS)) {
                    const auto* values = static_cast<const uint32_t*>(RTA_DATA(attr));
                    info->rmem = values[SK_MEMINFO_RMEM_ALLOC];
                    info->wmem = values[SK_MEMINFO_WMEM_ALLOC];
                    info->drops = values[SK_MEMINFO_DROPS];
                }
                break;
            }
            case INET_DIAG_CONG:
                info->congestion = attr_string(attr);
                break;
            default:
                break;
        }
    }
}

void parse_inet_diag_message(const inet_diag_msg& msg, int attr_len, const std::string& proto,
                             std::map<uint64_t, SocketInfo>* by_inode) {
    if (msg.idiag_inode == 0) {
        return;
    }

    SocketInfo info;
    info.source = "diag";
    info.proto = proto;
    info.local_addr = inet_diag_endpoint(msg.idiag_family, msg.id.idiag_src, msg.id.idiag_sport);
    info.remote_addr = inet_diag_endpoint(msg.idiag_family, msg.id.idiag_dst, msg.id.idiag_dport);
    info.state = tcp_state_name(msg.idiag_state);
    info.rqueue = msg.idiag_rqueue;
    info.wqueue = msg.idiag_wqueue;
    parse_inet_diag_attrs(msg, attr_len, &info);
    (*by_inode)[msg.idiag_inode] = info;
}

void recv_diag_dump(int fd, const std::string& proto, std::map<uint64_t, SocketInfo>* by_inode) {
    std::array<char, 32768> buffer{};
    while (true) {
        ssize_t n = ::recv(fd, buffer.data(), buffer.size(), 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (n == 0) {
            return;
        }

        auto* header = reinterpret_cast<nlmsghdr*>(buffer.data());
        for (; NLMSG_OK(header, n); header = NLMSG_NEXT(header, n)) {
            if (header->nlmsg_type == NLMSG_DONE || header->nlmsg_type == NLMSG_ERROR) {
                return;
            }
            if (header->nlmsg_type != SOCK_DIAG_BY_FAMILY) {
                continue;
            }
            auto* msg = reinterpret_cast<inet_diag_msg*>(NLMSG_DATA(header));
            int attr_len = 0;
            if (header->nlmsg_len >= NLMSG_LENGTH(sizeof(*msg))) {
                attr_len = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(*msg)));
            }
            parse_inet_diag_message(*msg, attr_len, proto, by_inode);
        }
    }
}

void send_inet_diag_dump(int fd, int family, int protocol, const std::string& proto,
                         std::map<uint64_t, SocketInfo>* by_inode) {
    struct Request {
        nlmsghdr header;
        inet_diag_req_v2 request;
    } req{};

    req.header.nlmsg_len = sizeof(req);
    req.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    req.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.header.nlmsg_seq = 1;
    req.request.sdiag_family = static_cast<uint8_t>(family);
    req.request.sdiag_protocol = static_cast<uint8_t>(protocol);
    req.request.idiag_ext =
        static_cast<uint8_t>((1U << (INET_DIAG_MEMINFO - 1)) | (1U << (INET_DIAG_INFO - 1)) |
                             (1U << (INET_DIAG_CONG - 1)) | (1U << (INET_DIAG_SKMEMINFO - 1)));
    req.request.idiag_states = 0xffffffffu;

    if (::send(fd, &req, sizeof(req), 0) < 0) {
        return;
    }
    recv_diag_dump(fd, proto, by_inode);
}

std::map<uint64_t, SocketInfo> load_inet_diag() {
    std::map<uint64_t, SocketInfo> by_inode;
    UniqueFd fd(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG));
    if (!fd) {
        return by_inode;
    }

    send_inet_diag_dump(fd.get(), AF_INET, IPPROTO_TCP, "TCP", &by_inode);
    send_inet_diag_dump(fd.get(), AF_INET6, IPPROTO_TCP, "TCP6", &by_inode);
    send_inet_diag_dump(fd.get(), AF_INET, IPPROTO_UDP, "UDP", &by_inode);
    send_inet_diag_dump(fd.get(), AF_INET6, IPPROTO_UDP, "UDP6", &by_inode);
    return by_inode;
}

std::string unix_socket_type_name(uint8_t type) {
    switch (type) {
        case SOCK_STREAM:
            return "UNIX-STREAM";
        case SOCK_DGRAM:
            return "UNIX-DGRAM";
        case SOCK_SEQPACKET:
            return "UNIX-SEQPACKET";
        default:
            return "UNIX";
    }
}

void parse_unix_diag_attrs(const unix_diag_msg& msg, int attr_len, SocketInfo* info) {
    auto* attr = reinterpret_cast<rtattr*>(
        const_cast<char*>(reinterpret_cast<const char*>(&msg) + sizeof(unix_diag_msg)));
    for (; RTA_OK(attr, attr_len); attr = RTA_NEXT(attr, attr_len)) {
        switch (attr->rta_type) {
            case UNIX_DIAG_NAME:
                info->path = attr_string(attr);
                if (!info->path.empty()) {
                    info->local_addr = info->path;
                }
                break;
            case UNIX_DIAG_PEER: {
                auto peer = attr_value<uint32_t>(attr);
                if (peer) {
                    info->peer_inode = *peer;
                    std::ostringstream out;
                    out << "peer_inode:" << *peer;
                    info->remote_addr = out.str();
                }
                break;
            }
            case UNIX_DIAG_RQLEN: {
                auto qlen = attr_value<unix_diag_rqlen>(attr);
                if (qlen) {
                    info->unix_rqueue = qlen->udiag_rqueue;
                    info->unix_wqueue = qlen->udiag_wqueue;
                }
                break;
            }
            case UNIX_DIAG_MEMINFO:
                if (RTA_PAYLOAD(attr) >= static_cast<int>(sizeof(uint32_t) * SK_MEMINFO_VARS)) {
                    const auto* values = static_cast<const uint32_t*>(RTA_DATA(attr));
                    info->rmem = values[SK_MEMINFO_RMEM_ALLOC];
                    info->wmem = values[SK_MEMINFO_WMEM_ALLOC];
                    info->drops = values[SK_MEMINFO_DROPS];
                }
                break;
            default:
                break;
        }
    }
}

void parse_unix_diag_message(const unix_diag_msg& msg, int attr_len,
                             std::map<uint64_t, SocketInfo>* by_inode) {
    if (msg.udiag_ino == 0) {
        return;
    }

    SocketInfo info;
    info.source = "diag";
    info.proto = unix_socket_type_name(msg.udiag_type);
    info.state = tcp_state_name(msg.udiag_state);
    parse_unix_diag_attrs(msg, attr_len, &info);
    (*by_inode)[msg.udiag_ino] = info;
}

void recv_unix_diag_dump(int fd, std::map<uint64_t, SocketInfo>* by_inode) {
    std::array<char, 32768> buffer{};
    while (true) {
        ssize_t n = ::recv(fd, buffer.data(), buffer.size(), 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (n == 0) {
            return;
        }

        auto* header = reinterpret_cast<nlmsghdr*>(buffer.data());
        for (; NLMSG_OK(header, n); header = NLMSG_NEXT(header, n)) {
            if (header->nlmsg_type == NLMSG_DONE || header->nlmsg_type == NLMSG_ERROR) {
                return;
            }
            if (header->nlmsg_type != SOCK_DIAG_BY_FAMILY) {
                continue;
            }
            auto* msg = reinterpret_cast<unix_diag_msg*>(NLMSG_DATA(header));
            int attr_len = 0;
            if (header->nlmsg_len >= NLMSG_LENGTH(sizeof(*msg))) {
                attr_len = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(*msg)));
            }
            parse_unix_diag_message(*msg, attr_len, by_inode);
        }
    }
}

std::map<uint64_t, SocketInfo> load_unix_diag() {
    std::map<uint64_t, SocketInfo> by_inode;
    UniqueFd fd(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG));
    if (!fd) {
        return by_inode;
    }

    struct Request {
        nlmsghdr header;
        unix_diag_req request;
    } req{};

    req.header.nlmsg_len = sizeof(req);
    req.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    req.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.header.nlmsg_seq = 1;
    req.request.sdiag_family = AF_UNIX;
    req.request.udiag_states = 0xffffffffu;
    req.request.udiag_show =
        UDIAG_SHOW_NAME | UDIAG_SHOW_PEER | UDIAG_SHOW_RQLEN | UDIAG_SHOW_MEMINFO;

    if (::send(fd.get(), &req, sizeof(req), 0) < 0) {
        return by_inode;
    }
    recv_unix_diag_dump(fd.get(), &by_inode);
    return by_inode;
}

void merge_socket_maps(std::map<uint64_t, SocketInfo>* target,
                       const std::map<uint64_t, SocketInfo>& source) {
    for (const auto& item : source) {
        (*target)[item.first] = item.second;
    }
}

std::optional<bool> same_namespace(const std::string& left, const std::string& right) {
    struct stat left_st {};
    struct stat right_st {};
    if (::stat(left.c_str(), &left_st) != 0 || ::stat(right.c_str(), &right_st) != 0) {
        return std::nullopt;
    }
    return left_st.st_dev == right_st.st_dev && left_st.st_ino == right_st.st_ino;
}

std::map<uint64_t, SocketInfo> load_socket_diag_current_netns() {
    std::map<uint64_t, SocketInfo> by_inode = load_inet_diag();
    merge_socket_maps(&by_inode, load_unix_diag());
    return by_inode;
}

bool socket_field_conflict(const std::string& local, const std::string& diag) {
    if (local == "UNIX" && starts_with(diag, "UNIX-")) {
        return false;
    }
    return !local.empty() && !diag.empty() && local != diag;
}

}  // namespace

void fill_socket_info(int fd, FdEntry* entry) {
    SocketInfo info;
    info.source = "local";

    int domain = 0;
    int type = 0;
    int protocol = 0;
    get_socket_option(fd, SOL_SOCKET, SO_DOMAIN, &domain);
    get_socket_option(fd, SOL_SOCKET, SO_TYPE, &type);
    get_socket_option(fd, SOL_SOCKET, SO_PROTOCOL, &protocol);

    if (domain == AF_UNIX) {
        info.proto = "UNIX";
    } else if (protocol == IPPROTO_TCP) {
        info.proto = domain == AF_INET6 ? "TCP6" : "TCP";
    } else if (protocol == IPPROTO_UDP) {
        info.proto = domain == AF_INET6 ? "UDP6" : "UDP";
    } else if (type == SOCK_STREAM) {
        info.proto = "STREAM";
    } else if (type == SOCK_DGRAM) {
        info.proto = "DGRAM";
    } else {
        info.proto = "SOCKET";
    }

    sockaddr_storage local{};
    socklen_t local_len = sizeof(local);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&local), &local_len) == 0) {
        info.local_addr = endpoint_to_string(local);
    }

    sockaddr_storage remote{};
    socklen_t remote_len = sizeof(remote);
    if (::getpeername(fd, reinterpret_cast<sockaddr*>(&remote), &remote_len) == 0) {
        info.remote_addr = endpoint_to_string(remote);
    }

    if (protocol == IPPROTO_TCP) {
        tcp_info tcp{};
        socklen_t len = sizeof(tcp);
        if (::getsockopt(fd, IPPROTO_TCP, TCP_INFO, &tcp, &len) == 0) {
            info.has_tcp_info = true;
            info.state = tcp_state_name(tcp.tcpi_state);
            info.rtt_us = tcp.tcpi_rtt;
            info.snd_cwnd = tcp.tcpi_snd_cwnd;
            info.retrans = tcp.tcpi_retrans;
        }
    }

    entry->socket = info;
}

std::map<uint64_t, SocketInfo> load_socket_diag_for_pid(int pid) {
    std::ostringstream target_path;
    target_path << "/proc/" << pid << "/ns/net";
    const std::string self_path = "/proc/self/ns/net";

    std::optional<bool> same_netns = same_namespace(self_path, target_path.str());
    if (!same_netns) {
        return {};
    }
    if (*same_netns) {
        return load_socket_diag_current_netns();
    }

    UniqueFd self(::open(self_path.c_str(), O_RDONLY | O_CLOEXEC));
    UniqueFd target(::open(target_path.str().c_str(), O_RDONLY | O_CLOEXEC));
    if (!self || !target || ::setns(target.get(), CLONE_NEWNET) != 0) {
        return {};
    }

    std::map<uint64_t, SocketInfo> by_inode = load_socket_diag_current_netns();
    if (::setns(self.get(), CLONE_NEWNET) != 0) {
        throw errno_error("restore network namespace");
    }
    return by_inode;
}

void attach_diag_info(const std::map<uint64_t, SocketInfo>& by_inode, FdEntry* entry) {
    auto it = by_inode.find(entry->inode);
    if (it == by_inode.end()) {
        return;
    }

    if (!entry->socket) {
        entry->socket = it->second;
        return;
    }

    const SocketInfo local = *entry->socket;
    const SocketInfo& diag = it->second;
    SocketInfo merged = diag;
    merged.source_conflict = socket_field_conflict(local.proto, diag.proto) ||
                             socket_field_conflict(local.local_addr, diag.local_addr) ||
                             socket_field_conflict(local.remote_addr, diag.remote_addr) ||
                             socket_field_conflict(local.state, diag.state);
    if (!merged.has_tcp_info && local.has_tcp_info) {
        merged.has_tcp_info = true;
        merged.rtt_us = local.rtt_us;
        merged.snd_cwnd = local.snd_cwnd;
        merged.retrans = local.retrans;
        if (merged.state.empty()) {
            merged.state = local.state;
        }
        merged.source = "diag+local-tcp";
    }
    entry->socket = merged;
}

}  // namespace fdi::detail
