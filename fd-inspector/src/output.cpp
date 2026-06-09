#include "fd_inspector.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>

namespace fdi {
namespace {

std::string json_escape(const std::string& input) {
    std::ostringstream out;
    for (char c : input) {
        switch (c) {
            case '\\':
                out << "\\\\";
                break;
            case '"':
                out << "\\\"";
                break;
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(static_cast<unsigned char>(c)) << std::dec
                        << std::setfill(' ');
                } else {
                    out << c;
                }
                break;
        }
    }
    return out.str();
}

std::string socket_summary(const FdEntry& entry) {
    if (!entry.socket) {
        return {};
    }

    const SocketInfo& socket = *entry.socket;
    std::ostringstream out;
    out << socket.proto;
    if (!socket.local_addr.empty()) {
        out << ' ' << socket.local_addr;
    }
    if (!socket.remote_addr.empty()) {
        out << " -> " << socket.remote_addr;
    }
    if (!socket.state.empty()) {
        out << ' ' << socket.state;
    }
    if (!socket.congestion.empty()) {
        out << " cc=" << socket.congestion;
    }
    if (socket.rqueue || socket.wqueue) {
        out << " q=" << socket.rqueue.value_or(0) << '/' << socket.wqueue.value_or(0);
    }
    if (socket.has_tcp_info) {
        out << " [rtt=" << socket.rtt_us << "us cwnd=" << socket.snd_cwnd
            << " retrans=" << socket.retrans << ']';
    }
    if (!socket.source.empty()) {
        out << " src=" << socket.source;
    }
    if (socket.source_conflict) {
        out << " conflict";
    }
    return out.str();
}

std::string fdinfo_summary(const FdEntry& entry) {
    std::ostringstream out;
    if (!entry.epoll_targets.empty()) {
        out << " epoll_targets=" << entry.epoll_targets.size();
    }
    if (entry.eventfd_count) {
        out << " eventfd_count=" << *entry.eventfd_count;
    }
    if (entry.timerfd_ticks) {
        out << " timerfd_ticks=" << *entry.timerfd_ticks;
    }
    if (entry.signal_mask) {
        out << " sigmask=" << *entry.signal_mask;
    }
    if (!entry.inotify_watches.empty()) {
        out << " inotify_watches=" << entry.inotify_watches.size();
    }
    if (!entry.fanotify_marks.empty()) {
        out << " fanotify_marks=" << entry.fanotify_marks.size();
    }
    if (!entry.mount_point.empty()) {
        out << " mnt=" << entry.mount_point;
    }
    if (entry.fs_type != 0) {
        out << " fs=0x" << std::hex << entry.fs_type << std::dec;
    }
    if (entry.deleted && entry.size != 0) {
        out << " size=" << entry.size;
    }
    return out.str();
}

bool should_print(const FdEntry& entry, bool only_socket) {
    return !only_socket || entry.type == FdType::Socket;
}

void print_socket_json(std::ostream& out, const SocketInfo& socket) {
    out << ",\"socket\":{";
    out << "\"proto\":\"" << json_escape(socket.proto) << "\"";
    out << ",\"local\":\"" << json_escape(socket.local_addr) << "\"";
    out << ",\"remote\":\"" << json_escape(socket.remote_addr) << "\"";
    out << ",\"state\":\"" << json_escape(socket.state) << "\"";
    out << ",\"path\":\"" << json_escape(socket.path) << "\"";
    out << ",\"source\":\"" << json_escape(socket.source) << "\"";
    out << ",\"source_conflict\":" << (socket.source_conflict ? "true" : "false");
    out << ",\"has_tcp_info\":" << (socket.has_tcp_info ? "true" : "false");
    out << ",\"rtt_us\":" << socket.rtt_us;
    out << ",\"snd_cwnd\":" << socket.snd_cwnd;
    out << ",\"retrans\":" << socket.retrans;
    if (socket.rqueue) {
        out << ",\"rqueue\":" << *socket.rqueue;
    }
    if (socket.wqueue) {
        out << ",\"wqueue\":" << *socket.wqueue;
    }
    if (socket.rmem) {
        out << ",\"rmem\":" << *socket.rmem;
    }
    if (socket.wmem) {
        out << ",\"wmem\":" << *socket.wmem;
    }
    if (socket.drops) {
        out << ",\"drops\":" << *socket.drops;
    }
    if (socket.peer_inode) {
        out << ",\"peer_inode\":" << *socket.peer_inode;
    }
    if (socket.unix_rqueue) {
        out << ",\"unix_rqueue\":" << *socket.unix_rqueue;
    }
    if (socket.unix_wqueue) {
        out << ",\"unix_wqueue\":" << *socket.unix_wqueue;
    }
    if (!socket.congestion.empty()) {
        out << ",\"congestion\":\"" << json_escape(socket.congestion) << "\"";
    }
    out << '}';
}

void print_epoll_targets_json(std::ostream& out, const std::vector<EpollTarget>& targets) {
    out << ",\"epoll_targets\":[";
    for (size_t i = 0; i < targets.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        out << "{";
        out << "\"fd\":" << targets[i].fd;
        out << ",\"events\":\"" << json_escape(targets[i].events) << "\"";
        out << ",\"data\":\"" << json_escape(targets[i].data) << "\"";
        out << "}";
    }
    out << "]";
}

void print_inotify_watches_json(std::ostream& out, const std::vector<InotifyWatch>& watches) {
    out << ",\"inotify_watches\":[";
    for (size_t i = 0; i < watches.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        out << "{";
        out << "\"wd\":" << watches[i].wd;
        out << ",\"inode\":" << watches[i].inode;
        out << ",\"device\":\"" << json_escape(watches[i].device) << "\"";
        out << ",\"mask\":\"" << json_escape(watches[i].mask) << "\"";
        out << ",\"ignored_mask\":\"" << json_escape(watches[i].ignored_mask) << "\"";
        out << ",\"file_handle\":\"" << json_escape(watches[i].file_handle) << "\"";
        out << "}";
    }
    out << "]";
}

void print_fanotify_marks_json(std::ostream& out, const std::vector<FanotifyMark>& marks) {
    out << ",\"fanotify_marks\":[";
    for (size_t i = 0; i < marks.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        out << "{";
        if (marks[i].mnt_id) {
            out << "\"mnt_id\":" << *marks[i].mnt_id;
        } else {
            out << "\"mnt_id\":null";
        }
        out << ",\"inode\":" << marks[i].inode;
        out << ",\"device\":\"" << json_escape(marks[i].device) << "\"";
        out << ",\"mark_flags\":\"" << json_escape(marks[i].mark_flags) << "\"";
        out << ",\"mask\":\"" << json_escape(marks[i].mask) << "\"";
        out << ",\"ignored_mask\":\"" << json_escape(marks[i].ignored_mask) << "\"";
        out << ",\"file_handle\":\"" << json_escape(marks[i].file_handle) << "\"";
        out << "}";
    }
    out << "]";
}

void print_optional_fdinfo_json(std::ostream& out, const FdEntry& entry) {
    if (entry.pos) {
        out << ",\"pos\":" << *entry.pos;
    }
    if (entry.fdinfo_flags) {
        out << ",\"fdinfo_flags\":" << *entry.fdinfo_flags;
    }
    if (entry.mnt_id) {
        out << ",\"mnt_id\":" << *entry.mnt_id;
    }
    if (entry.fdinfo_inode) {
        out << ",\"fdinfo_inode\":" << *entry.fdinfo_inode;
    }
    if (!entry.epoll_targets.empty()) {
        print_epoll_targets_json(out, entry.epoll_targets);
    }
    if (entry.eventfd_count) {
        out << ",\"eventfd_count\":" << *entry.eventfd_count;
    }
    if (entry.eventfd_id) {
        out << ",\"eventfd_id\":" << *entry.eventfd_id;
    }
    if (entry.timerfd_clockid) {
        out << ",\"timerfd_clockid\":" << *entry.timerfd_clockid;
    }
    if (entry.timerfd_ticks) {
        out << ",\"timerfd_ticks\":" << *entry.timerfd_ticks;
    }
    if (entry.signal_mask) {
        out << ",\"signal_mask\":\"" << json_escape(*entry.signal_mask) << "\"";
    }
    if (!entry.inotify_watches.empty()) {
        print_inotify_watches_json(out, entry.inotify_watches);
    }
    if (!entry.fanotify_marks.empty()) {
        print_fanotify_marks_json(out, entry.fanotify_marks);
    }
}

}  // namespace

void print_table(std::ostream& out, const std::vector<FdEntry>& entries, bool only_socket) {
    out << std::left << std::setw(6) << "FD" << std::setw(10) << "TYPE"
        << "TARGET\n";
    for (const FdEntry& entry : entries) {
        if (!should_print(entry, only_socket)) {
            continue;
        }

        std::string target = entry.target;
        std::string socket = socket_summary(entry);
        if (!socket.empty()) {
            target = socket;
        }
        target += fdinfo_summary(entry);

        out << std::left << std::setw(6) << entry.fd << std::setw(10) << type_name(entry.type)
            << target << '\n';
    }
}

void print_json(std::ostream& out, const std::vector<FdEntry>& entries, bool only_socket) {
    out << "[";
    bool first = true;
    for (const FdEntry& entry : entries) {
        if (!should_print(entry, only_socket)) {
            continue;
        }
        if (!first) {
            out << ",";
        }
        first = false;

        out << "{";
        out << "\"fd\":" << entry.fd;
        out << ",\"type\":\"" << type_name(entry.type) << "\"";
        out << ",\"target\":\"" << json_escape(entry.target) << "\"";
        out << ",\"inode\":" << entry.inode;
        out << ",\"flags\":" << entry.flags;
        out << ",\"fd_flags\":" << entry.fd_flags;
        out << ",\"flags_valid\":" << (entry.flags_valid ? "true" : "false");
        out << ",\"fd_flags_valid\":" << (entry.fd_flags_valid ? "true" : "false");
        out << ",\"deleted\":" << (entry.deleted ? "true" : "false");
        out << ",\"size\":" << entry.size;
        out << ",\"device\":" << entry.device;
        out << ",\"fs_type\":" << entry.fs_type;
        out << ",\"mount_point\":\"" << json_escape(entry.mount_point) << "\"";
        out << ",\"mount_root\":\"" << json_escape(entry.mount_root) << "\"";
        print_optional_fdinfo_json(out, entry);
        if (entry.socket) {
            print_socket_json(out, *entry.socket);
        }
        out << "}";
    }
    out << "]\n";
}

void print_leak_report(std::ostream& out, const LeakReport& report, bool json) {
    if (json) {
        out << "{";
        out << "\"suspected\":" << (report.suspected ? "true" : "false");
        out << ",\"verdict\":\"" << json_escape(report.verdict) << "\"";
        out << ",\"file_growth\":" << report.file_growth;
        out << ",\"socket_growth\":" << report.socket_growth;
        out << ",\"pipe_growth\":" << report.pipe_growth;
        out << ",\"total_growth\":" << report.total_growth;
        out << ",\"close_wait_count\":" << report.close_wait_count;
        out << ",\"sample_count\":" << report.sample_count;
        out << ",\"monotonic_growth\":" << (report.monotonic_growth ? "true" : "false");
        out << ",\"first_total\":" << report.first.size();
        out << ",\"last_total\":" << report.last.size();
        out << ",\"new_targets\":[";
        for (size_t i = 0; i < report.new_targets.size(); ++i) {
            if (i != 0) {
                out << ",";
            }
            out << "\"" << json_escape(report.new_targets[i]) << "\"";
        }
        out << "]";
        out << ",\"growth_buckets\":[";
        for (size_t i = 0; i < report.growth_buckets.size(); ++i) {
            if (i != 0) {
                out << ",";
            }
            out << "{";
            out << "\"key\":\"" << json_escape(report.growth_buckets[i].key) << "\"";
            out << ",\"growth\":" << report.growth_buckets[i].growth;
            out << "}";
        }
        out << "]";
        out << "}\n";
        return;
    }

    out << report.verdict << '\n';
    out << "first_total=" << report.first.size() << " last_total=" << report.last.size()
        << " file_growth=" << report.file_growth << " socket_growth=" << report.socket_growth
        << " pipe_growth=" << report.pipe_growth << " total_growth=" << report.total_growth
        << " close_wait=" << report.close_wait_count << " samples=" << report.sample_count
        << " monotonic=" << (report.monotonic_growth ? "yes" : "no") << '\n';
    if (!report.new_targets.empty()) {
        out << "new_targets:\n";
        for (const std::string& target : report.new_targets) {
            out << "  " << target << '\n';
        }
    }
    if (!report.growth_buckets.empty()) {
        out << "growth_buckets:\n";
        for (const GrowthBucket& bucket : report.growth_buckets) {
            out << "  +" << bucket.growth << " " << bucket.key << '\n';
        }
    }
}

}  // namespace fdi
