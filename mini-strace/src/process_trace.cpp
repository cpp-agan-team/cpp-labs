#include "internal.hpp"

#include <algorithm>
#include <ostream>
#include <string>

namespace mini_strace {
namespace detail {
namespace {

bool is_fork_like(const std::string& name) {
    return name == "fork" || name == "vfork";
}

bool is_clone_like(const std::string& name) {
    return name == "clone" || name == "clone3";
}

bool is_resource_syscall(const std::string& name) {
    return name == "statx" || name == "newfstatat" || name == "prlimit64" || name == "close_range";
}

std::string arg_value(const SyscallEvent& event, const std::string& name) {
    for (const auto& arg : event.decoded_args) {
        if (arg.name == name) {
            return arg.value;
        }
    }
    return "";
}

}  // namespace

void ProcessSummary::observe(const SyscallEvent& event) {
    if (event.is_error) {
        if (is_fork_like(event.name) || is_clone_like(event.name) || event.name == "wait4" ||
            event.name == "execve" || event.name == "execveat" || is_resource_syscall(event.name)) {
            ++errors_;
        }
    }
    if (is_resource_syscall(event.name)) {
        auto& stats = resources_[event.name];
        ++stats.count;
        if (event.is_error) {
            ++stats.errors;
        }
        return;
    }
    if (event.is_error) {
        return;
    }
    if (is_fork_like(event.name) && event.raw_ret > 0) {
        ++fork_events_;
        children_.push_back(ProcessChild{event.pid, static_cast<pid_t>(event.raw_ret), event.name});
        return;
    }
    if (is_clone_like(event.name) && event.raw_ret > 0) {
        ++clone_events_;
        children_.push_back(ProcessChild{event.pid, static_cast<pid_t>(event.raw_ret), event.name});
        return;
    }
    if (event.name == "execve" || event.name == "execveat") {
        ++exec_events_;
        return;
    }
    if (event.name == "wait4" && event.raw_ret > 0) {
        ++wait_events_;
        waits_.push_back(
            ProcessWait{event.pid, static_cast<pid_t>(event.raw_ret), arg_value(event, "status")});
        return;
    }
}

void ProcessSummary::write(std::ostream& out) const {
    out << "process:\n";
    if (fork_events_ == 0 && clone_events_ == 0 && exec_events_ == 0 && wait_events_ == 0 &&
        resources_.empty()) {
        out << "  no_process_events\n";
        return;
    }
    out << "  fork_events=" << fork_events_ << " clone_events=" << clone_events_
        << " exec_events=" << exec_events_ << " wait_events=" << wait_events_
        << " errors=" << errors_ << '\n';
    if (!children_.empty()) {
        out << "  children:\n";
        const auto limit = std::min<std::size_t>(children_.size(), 10);
        for (std::size_t i = 0; i < limit; ++i) {
            const auto& child = children_[i];
            out << "    pid=" << child.child << " parent=" << child.parent
                << " source=" << child.source << '\n';
        }
    }
    if (!waits_.empty()) {
        out << "  waits:\n";
        const auto limit = std::min<std::size_t>(waits_.size(), 10);
        for (std::size_t i = 0; i < limit; ++i) {
            const auto& wait = waits_[i];
            out << "    pid=" << wait.child << " parent=" << wait.parent;
            if (!wait.status.empty()) {
                out << " status=" << wait.status;
            }
            out << '\n';
        }
    }
    if (!resources_.empty()) {
        out << "  resources:\n";
        for (const auto& item : resources_) {
            out << "    " << item.first << ": calls=" << item.second.count
                << " errors=" << item.second.errors << '\n';
        }
    }
}

}  // namespace detail
}  // namespace mini_strace
