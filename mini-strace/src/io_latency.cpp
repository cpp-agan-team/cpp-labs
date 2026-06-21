#include "internal.hpp"

#include <algorithm>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace mini_strace {
namespace detail {
namespace {

bool is_io_syscall(const std::string& name) {
    return name == "read" || name == "write" || name == "pread64" || name == "pwrite64" ||
           name == "open" || name == "openat" || name == "openat2" || name == "close" ||
           name == "fsync" || name == "fdatasync" || name == "poll" || name == "ppoll" ||
           name == "epoll_wait" || name == "epoll_pwait" || name == "connect" || name == "accept" ||
           name == "accept4";
}

std::optional<std::string> decoded_value(const SyscallEvent& event, const std::string& name) {
    for (const auto& arg : event.decoded_args) {
        if (arg.name == name) {
            return arg.value;
        }
    }
    return std::nullopt;
}

std::string strip_quotes(std::string value) {
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        return value.substr(1, value.size() - 2);
    }
    if (value.size() >= 5 && value.front() == '"' && value.substr(value.size() - 4) == "...\"") {
        return value.substr(1, value.size() - 5);
    }
    return value;
}

std::optional<std::string> first_pollfd_label(const SyscallEvent& event) {
    const auto fds = decoded_value(event, "fds");
    if (!fds) {
        return std::nullopt;
    }
    const std::string marker = "fd=";
    const auto start = fds->find(marker);
    if (start == std::string::npos) {
        return std::nullopt;
    }
    const auto value_start = start + marker.size();
    const auto value_end = fds->find_first_of(",}", value_start);
    return "fd=" + fds->substr(value_start, value_end - value_start);
}

std::optional<std::string> fd_label(const SyscallEvent& event) {
    if (event.fd_context) {
        std::ostringstream out;
        out << "fd=" << event.fd_context->fd;
        if (!event.fd_context->kind.empty()) {
            out << " kind=" << event.fd_context->kind;
        }
        return out.str();
    }
    if (event.name == "open" || event.name == "openat" || event.name == "openat2") {
        if (!event.is_error && event.raw_ret >= 0) {
            return "fd=" + std::to_string(event.raw_ret);
        }
        return std::nullopt;
    }
    if (event.name == "poll" || event.name == "ppoll") {
        return first_pollfd_label(event);
    }
    return "fd=" + std::to_string(static_cast<long long>(event.raw_args[0]));
}

std::optional<std::string> path_label(const SyscallEvent& event) {
    if (event.fd_context && !event.fd_context->path.empty()) {
        return event.fd_context->path;
    }
    if (event.name == "open" || event.name == "openat" || event.name == "openat2") {
        if (const auto pathname = decoded_value(event, "pathname")) {
            return strip_quotes(*pathname);
        }
        return "<unknown-path>";
    }
    return std::nullopt;
}

void add_sample(IoLatencyStats& stats, const SyscallEvent& event, std::uint64_t slow_ns) {
    ++stats.count;
    if (event.is_error) {
        ++stats.errors;
    }
    if (event.duration_ns >= slow_ns) {
        ++stats.slow;
    }
    stats.total_ns += event.duration_ns;
    stats.max_ns = std::max(stats.max_ns, event.duration_ns);
}

double ns_to_us(std::uint64_t ns) {
    return static_cast<double>(ns) / 1000.0;
}

std::string format_stats(const IoLatencyStats& stats) {
    const double avg_us = stats.count == 0 ? 0.0 : ns_to_us(stats.total_ns) / stats.count;
    std::ostringstream out;
    out << "calls=" << stats.count << " errors=" << stats.errors << " slow=" << stats.slow
        << " total_us=" << std::fixed << std::setprecision(3) << ns_to_us(stats.total_ns)
        << " avg_us=" << avg_us << " max_us=" << ns_to_us(stats.max_ns);
    return out.str();
}

std::vector<std::pair<std::string, IoLatencyStats>> sorted_stats(
    const std::map<std::string, IoLatencyStats>& values) {
    std::vector<std::pair<std::string, IoLatencyStats>> sorted(values.begin(), values.end());
    std::sort(sorted.begin(), sorted.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.second.total_ns != rhs.second.total_ns) {
            return lhs.second.total_ns > rhs.second.total_ns;
        }
        return lhs.first < rhs.first;
    });
    return sorted;
}

void write_group(std::ostream& out, const std::string& name,
                 const std::map<std::string, IoLatencyStats>& values) {
    if (values.empty()) {
        return;
    }
    constexpr std::size_t kMaxRows = 10;
    out << "  " << name << ":\n";
    const auto sorted = sorted_stats(values);
    const std::size_t rows = std::min(kMaxRows, sorted.size());
    for (std::size_t i = 0; i < rows; ++i) {
        out << "    " << sorted[i].first << ": " << format_stats(sorted[i].second) << '\n';
    }
}

}  // namespace

IoLatencySummary::IoLatencySummary(std::uint64_t slow_threshold_us)
    : slow_threshold_ns_(slow_threshold_us * 1000) {}

void IoLatencySummary::observe(const SyscallEvent& event) {
    if (!is_io_syscall(event.name)) {
        return;
    }
    add_sample(by_syscall_[event.name], event, slow_threshold_ns_);
    if (const auto fd = fd_label(event)) {
        add_sample(by_fd_[*fd], event, slow_threshold_ns_);
    }
    if (const auto path = path_label(event)) {
        add_sample(by_path_[*path], event, slow_threshold_ns_);
    }
}

void IoLatencySummary::write(std::ostream& out) const {
    out << "io_latency:\n";
    if (by_syscall_.empty()) {
        out << "  no_io_events\n";
        return;
    }
    out << "  slow_threshold_us: " << (slow_threshold_ns_ / 1000) << '\n';
    write_group(out, "by_syscall", by_syscall_);
    write_group(out, "by_fd", by_fd_);
    write_group(out, "by_path", by_path_);
}

}  // namespace detail
}  // namespace mini_strace
