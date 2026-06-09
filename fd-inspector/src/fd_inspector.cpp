#include "fd_inspector.hpp"

#include "fd_inspector_internal.hpp"
#include "unique_fd.hpp"

#include <algorithm>
#include <cerrno>
#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <vector>

namespace fdi {

std::vector<FdEntry> inspect_pid(int pid, const InspectOptions& options) {
    using namespace detail;

    UniqueFd pidfd(options.force_proc_fallback ? -1 : syscall_pidfd_open(pid));
    int pidfd_open_error = pidfd ? 0 : errno;
    if (!pidfd && !options.force_proc_fallback) {
        if (errno == ESRCH) {
            throw errno_error("pidfd_open; process exited");
        }
        if (is_permission_error(pidfd_open_error)) {
            warn_permission_fallback("pidfd_open", pidfd_open_error);
        }
    }

    int max_fd = scan_limit_for_pid(pid, options);
    std::map<uint64_t, SocketInfo> diag_by_inode = load_socket_diag_for_pid(pid);
    std::map<int, MountInfo> mounts = read_mountinfo(pid);

    bool used_range_fallback = false;
    int skipped_for_limit = 0;
    std::vector<int> target_fds =
        list_target_fds(pid, max_fd, &used_range_fallback, &skipped_for_limit);
    if (skipped_for_limit > 0) {
        std::cerr << "fd-inspector: skipped " << skipped_for_limit << " fd(s) >= --max-fd "
                  << max_fd << "; use --max-fd 0 for RLIMIT_NOFILE or a larger explicit limit.\n";
    }
    if (!pidfd && used_range_fallback) {
        throw std::runtime_error(
            "cannot inspect: pidfd is unavailable and /proc/<pid>/fd is unreadable");
    }

    std::optional<std::map<int, ProcFdSnapshot>> proc_snapshots;
    if (options.use_io_uring) {
        proc_snapshots = read_proc_fd_snapshots_io_uring(pid, target_fds);
    }

    std::vector<FdEntry> entries;
    bool warned_getfd_permission = false;
    for (int fd : target_fds) {
        const ProcFdSnapshot* snapshot = nullptr;
        if (proc_snapshots) {
            auto snapshot_it = proc_snapshots->find(fd);
            if (snapshot_it != proc_snapshots->end()) {
                snapshot = &snapshot_it->second;
            }
        }

        errno = 0;
        UniqueFd copied(pidfd ? syscall_pidfd_getfd(pidfd.get(), fd) : -1);
        if (!copied) {
            if (errno == EBADF) {
                continue;
            }
            if (errno == ESRCH) {
                throw errno_error("pidfd_getfd; process exited");
            }
            if (pidfd && is_permission_error(errno) && !warned_getfd_permission) {
                warn_permission_fallback("pidfd_getfd", errno);
                warned_getfd_permission = true;
            }

            FdEntry entry;
            inspect_proc_fd(pid, fd, snapshot, &entry);
            read_fdinfo(pid, &entry);
            if (entry.fdinfo_flags) {
                entry.flags = *entry.fdinfo_flags;
                entry.flags_valid = true;
            }
            if (entry.inode == 0 && entry.fdinfo_inode) {
                entry.inode = *entry.fdinfo_inode;
            }
            attach_mount_info(mounts, &entry);
            if (entry.type == FdType::Socket) {
                attach_diag_info(diag_by_inode, &entry);
            }
            if (!entry.target.empty() || entry.inode != 0 || entry.fdinfo_inode) {
                entries.push_back(std::move(entry));
            }
            continue;
        }

        FdEntry entry;
        inspect_copied_fd(copied.get(), fd, snapshot, &entry);
        read_fdinfo(pid, &entry);
        attach_mount_info(mounts, &entry);
        if (entry.type == FdType::Socket) {
            attach_diag_info(diag_by_inode, &entry);
        }
        entries.push_back(std::move(entry));
    }

    std::sort(entries.begin(), entries.end(),
              [](const FdEntry& a, const FdEntry& b) { return a.fd < b.fd; });
    return entries;
}

const char* type_name(FdType type) {
    switch (type) {
        case FdType::File:
            return "file";
        case FdType::Dir:
            return "dir";
        case FdType::CharDev:
            return "char";
        case FdType::BlockDev:
            return "block";
        case FdType::Fifo:
            return "fifo";
        case FdType::Pipe:
            return "pipe";
        case FdType::Socket:
            return "socket";
        case FdType::EventPoll:
            return "epoll";
        case FdType::EventFd:
            return "eventfd";
        case FdType::TimerFd:
            return "timerfd";
        case FdType::SignalFd:
            return "signalfd";
        case FdType::Inotify:
            return "inotify";
        case FdType::Fanotify:
            return "fanotify";
        case FdType::AnonOther:
            return "anon";
        case FdType::Unknown:
            return "unknown";
    }
    return "unknown";
}

}  // namespace fdi
