#include "internal.hpp"

#include <algorithm>
#include <iomanip>
#include <linux/futex.h>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

namespace mini_strace {
namespace detail {
namespace {

std::optional<std::string> arg_value(const SyscallEvent& event, const std::string& name) {
    for (const auto& arg : event.decoded_args) {
        if (arg.name == name) {
            return arg.value;
        }
    }
    return std::nullopt;
}

std::string display_path(std::string value) {
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.size() - 2);
    }
    return value;
}

bool is_futex_wait_op(std::uint64_t op) {
    const int command = static_cast<int>(op) & FUTEX_CMD_MASK;
    return command == FUTEX_WAIT || command == FUTEX_WAIT_BITSET;
}

}  // namespace

void Summary::observe(const SyscallEvent& event) {
    auto& stat = stats_[event.name];
    ++stat.count;
    if (event.is_error) {
        ++stat.errors;
    }
    stat.total_ns += event.duration_ns;
    stat.max_ns = std::max(stat.max_ns, event.duration_ns);

    if (event.is_error && event.errno_name == "ENOENT" &&
        (event.name == "openat" || event.name == "open" || event.name == "newfstatat")) {
        if (const auto path = arg_value(event, "pathname")) {
            ++path_misses_[display_path(*path)];
        }
    }
    if (event.name == "write" && event.fd_context && !event.fd_context->path.empty()) {
        ++fd_writes_[event.fd_context->path];
    }
    if (!event.is_error && event.name == "mmap") {
        mmap_delta_ += static_cast<std::int64_t>(event.raw_args[1]);
    }
    if (!event.is_error && event.name == "munmap") {
        mmap_delta_ -= static_cast<std::int64_t>(event.raw_args[1]);
    }
    if (event.name == "futex" && is_futex_wait_op(event.raw_args[1])) {
        ++futex_wait_count_;
        if (event.is_error) {
            ++futex_wait_errors_;
        }
        futex_wait_total_ns_ += event.duration_ns;
        futex_wait_max_ns_ = std::max(futex_wait_max_ns_, event.duration_ns);
    }
    if (event.interrupted) {
        ++interrupted_syscalls_[event.name];
    }
    if (event.name == "restart_syscall") {
        ++restart_syscall_count_;
    }
}

void Summary::write(std::ostream& out) const {
    std::vector<std::pair<std::string, SyscallStats>> rows(stats_.begin(), stats_.end());
    std::sort(rows.begin(), rows.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.second.total_ns != rhs.second.total_ns) {
            return lhs.second.total_ns > rhs.second.total_ns;
        }
        return lhs.first < rhs.first;
    });

    out << "syscall        calls   errors   total_us   avg_us   max_us\n";
    for (const auto& row : rows) {
        const auto& name = row.first;
        const auto& stat = row.second;
        const double total_us = static_cast<double>(stat.total_ns) / 1000.0;
        const double avg_us = stat.count == 0 ? 0.0 : total_us / static_cast<double>(stat.count);
        const double max_us = static_cast<double>(stat.max_ns) / 1000.0;
        out << std::left << std::setw(14) << name << std::right << std::setw(7) << stat.count
            << std::setw(9) << stat.errors << std::setw(11) << std::fixed << std::setprecision(1)
            << total_us << std::setw(9) << avg_us << std::setw(9) << max_us << '\n';
    }
}

void Summary::write_diagnostics(std::ostream& out) const {
    out << "diagnostics:\n";
    if (!path_misses_.empty()) {
        out << "  path_misses:\n";
        for (const auto& item : path_misses_) {
            out << "    " << item.second << "x " << item.first << '\n';
        }
    }
    if (!fd_writes_.empty()) {
        out << "  fd_hotspots:\n";
        for (const auto& item : fd_writes_) {
            out << "    " << item.second << " writes " << item.first << '\n';
        }
    }
    if (futex_wait_count_ != 0) {
        out << "  futex_waits: calls=" << futex_wait_count_ << " errors=" << futex_wait_errors_
            << " total_us=" << std::fixed << std::setprecision(1)
            << (static_cast<double>(futex_wait_total_ns_) / 1000.0)
            << " max_us=" << (static_cast<double>(futex_wait_max_ns_) / 1000.0) << '\n';
    }
    if (!interrupted_syscalls_.empty()) {
        out << "  interrupted_syscalls:\n";
        for (const auto& item : interrupted_syscalls_) {
            out << "    " << item.second << "x " << item.first << '\n';
        }
    }
    if (restart_syscall_count_ != 0) {
        out << "  restart_syscalls: calls=" << restart_syscall_count_ << '\n';
    }
    out << "  mmap_delta_bytes: " << mmap_delta_ << '\n';
}

}  // namespace detail
}  // namespace mini_strace
