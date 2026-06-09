#include "fd_inspector_internal.hpp"
#include "unique_fd.hpp"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <liburing.h>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

#ifndef SYS_pidfd_open
#ifdef __NR_pidfd_open
#define SYS_pidfd_open __NR_pidfd_open
#endif
#endif

#ifndef SYS_pidfd_getfd
#ifdef __NR_pidfd_getfd
#define SYS_pidfd_getfd __NR_pidfd_getfd
#endif
#endif

namespace fdi::detail {
namespace {

std::string proc_fd_path(int pid, int target_fd) {
    std::ostringstream path;
    path << "/proc/" << pid << "/fd/" << target_fd;
    return path.str();
}

struct IoUringStatxRequest {
    int fd = -1;
    std::string path;
    struct statx stx {};
    int result = -EINVAL;
};

class IoUringQueue {
public:
    explicit IoUringQueue(unsigned entries) {
        initialized_ = ::io_uring_queue_init(entries, &ring_, 0) == 0;
    }

    ~IoUringQueue() {
        if (initialized_) {
            ::io_uring_queue_exit(&ring_);
        }
    }

    IoUringQueue(const IoUringQueue&) = delete;
    IoUringQueue& operator=(const IoUringQueue&) = delete;

    io_uring* get() { return &ring_; }
    explicit operator bool() const { return initialized_; }

private:
    io_uring ring_{};
    bool initialized_ = false;
};

bool submit_statx_batch(IoUringQueue* queue, std::vector<IoUringStatxRequest>* requests) {
    for (IoUringStatxRequest& request : *requests) {
        io_uring_sqe* sqe = ::io_uring_get_sqe(queue->get());
        if (!sqe) {
            return false;
        }
        ::io_uring_prep_statx(sqe, AT_FDCWD, request.path.c_str(), 0, STATX_BASIC_STATS,
                              &request.stx);
        ::io_uring_sqe_set_data(sqe, &request);
    }

    int submitted = ::io_uring_submit(queue->get());
    if (submitted != static_cast<int>(requests->size())) {
        return false;
    }

    for (int i = 0; i < submitted; ++i) {
        io_uring_cqe* cqe = nullptr;
        if (::io_uring_wait_cqe(queue->get(), &cqe) != 0) {
            return false;
        }
        auto* request = static_cast<IoUringStatxRequest*>(::io_uring_cqe_get_data(cqe));
        if (request) {
            request->result = cqe->res;
        }
        ::io_uring_cqe_seen(queue->get(), cqe);
    }
    return true;
}

std::vector<int> fallback_fd_range(int max_fd) {
    std::vector<int> fds;
    fds.reserve(static_cast<size_t>(max_fd));
    for (int fd = 0; fd < max_fd; ++fd) {
        fds.push_back(fd);
    }
    return fds;
}

}  // namespace

int syscall_pidfd_open(int pid) {
#ifdef SYS_pidfd_open
    return static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

int syscall_pidfd_getfd(int pidfd, int target_fd) {
#ifdef SYS_pidfd_getfd
    return static_cast<int>(::syscall(SYS_pidfd_getfd, pidfd, target_fd, 0));
#else
    (void)pidfd;
    (void)target_fd;
    errno = ENOSYS;
    return -1;
#endif
}

int scan_limit_for_pid(int pid, const InspectOptions& options) {
    if (options.max_fd > 0) {
        return options.max_fd;
    }

    rlimit limit{};
    if (::prlimit(pid, RLIMIT_NOFILE, nullptr, &limit) != 0) {
        throw errno_error("prlimit(RLIMIT_NOFILE)");
    }

    if (limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur > 65536) {
        return 65536;
    }
    return static_cast<int>(limit.rlim_cur);
}

std::vector<int> list_target_fds(int pid, int max_fd, bool* used_range_fallback,
                                 int* skipped_for_limit) {
    *used_range_fallback = false;
    *skipped_for_limit = 0;
    std::ostringstream path;
    path << "/proc/" << pid << "/fd";

    std::unique_ptr<DIR, int (*)(DIR*)> dir(::opendir(path.str().c_str()), ::closedir);
    if (!dir) {
        *used_range_fallback = true;
        return fallback_fd_range(max_fd);
    }

    std::vector<int> fds;
    while (dirent* entry = ::readdir(dir.get())) {
        int fd = -1;
        if (!parse_fd_name(entry->d_name, &fd)) {
            continue;
        }
        if (fd >= 0 && fd < max_fd) {
            fds.push_back(fd);
        } else if (fd >= max_fd) {
            ++(*skipped_for_limit);
        }
    }
    std::sort(fds.begin(), fds.end());
    fds.erase(std::unique(fds.begin(), fds.end()), fds.end());
    return fds;
}

std::optional<std::map<int, ProcFdSnapshot>> read_proc_fd_snapshots_io_uring(
    int pid, const std::vector<int>& fds) {
    constexpr size_t kBatchFds = 128;
    IoUringQueue queue(static_cast<unsigned>(kBatchFds));
    if (!queue) {
        return std::nullopt;
    }

    std::map<int, ProcFdSnapshot> snapshots;
    for (int fd : fds) {
        ProcFdSnapshot snapshot;
        snapshot.fd = fd;
        snapshot.target = read_target_fd_link(pid, fd);
        snapshot.has_target = !snapshot.target.empty();
        snapshots.emplace(fd, std::move(snapshot));
    }

    for (size_t begin = 0; begin < fds.size(); begin += kBatchFds) {
        size_t end = std::min(begin + kBatchFds, fds.size());
        std::vector<IoUringStatxRequest> requests;
        requests.reserve(end - begin);
        for (size_t i = begin; i < end; ++i) {
            IoUringStatxRequest request;
            request.fd = fds[i];
            request.path = proc_fd_path(pid, fds[i]);
            requests.push_back(std::move(request));
        }

        if (!submit_statx_batch(&queue, &requests)) {
            return std::nullopt;
        }
        for (const IoUringStatxRequest& request : requests) {
            auto it = snapshots.find(request.fd);
            if (it != snapshots.end() && request.result == 0) {
                it->second.stx = request.stx;
                it->second.has_statx = true;
            }
        }
    }
    return snapshots;
}

void inspect_copied_fd(int fd, int target_fd, const ProcFdSnapshot* snapshot, FdEntry* entry) {
    entry->fd = target_fd;
    if (snapshot && snapshot->has_target) {
        entry->target = snapshot->target;
    } else {
        entry->target = read_self_fd_target(fd);
    }
    entry->deleted = ends_with(entry->target, " (deleted)");
    int flags = ::fcntl(fd, F_GETFL);
    if (flags >= 0) {
        entry->flags = flags;
        entry->flags_valid = true;
    }
    int fd_flags = ::fcntl(fd, F_GETFD);
    if (fd_flags >= 0) {
        entry->fd_flags = fd_flags;
        entry->fd_flags_valid = true;
    }

    if (snapshot && snapshot->has_statx) {
        fill_entry_from_statx(snapshot->stx, entry);
    } else {
        struct stat st {};
        if (::fstat(fd, &st) == 0) {
            fill_entry_from_stat(st, entry);
        }
    }

    struct statfs fs {};
    if (::fstatfs(fd, &fs) == 0) {
        entry->fs_type = static_cast<long>(fs.f_type);
    }

    FdType target_type = type_from_target(entry->target);
    if (target_type != FdType::Unknown) {
        entry->type = target_type;
    }

    if (entry->type == FdType::Socket) {
        fill_socket_info(fd, entry);
    }
}

void inspect_proc_fd(int pid, int target_fd, const ProcFdSnapshot* snapshot, FdEntry* entry) {
    entry->fd = target_fd;
    if (snapshot && snapshot->has_target) {
        entry->target = snapshot->target;
    } else {
        entry->target = read_target_fd_link(pid, target_fd);
    }
    entry->deleted = ends_with(entry->target, " (deleted)");

    std::string path = proc_fd_path(pid, target_fd);

    if (snapshot && snapshot->has_statx) {
        fill_entry_from_statx(snapshot->stx, entry);
    } else {
        struct stat st {};
        if (::stat(path.c_str(), &st) == 0) {
            fill_entry_from_stat(st, entry);
        }
    }

    struct statfs fs {};
    if (::statfs(path.c_str(), &fs) == 0) {
        entry->fs_type = static_cast<long>(fs.f_type);
    }

    FdType target_type = type_from_target(entry->target);
    if (target_type != FdType::Unknown) {
        entry->type = target_type;
    }
    if (entry->inode == 0) {
        if (std::optional<uint64_t> inode = bracket_inode(entry->target, "socket:[")) {
            entry->inode = *inode;
        } else if (std::optional<uint64_t> pipe = bracket_inode(entry->target, "pipe:[")) {
            entry->inode = *pipe;
        }
    }
}

std::map<int, MountInfo> read_mountinfo(int pid) {
    std::ostringstream path;
    path << "/proc/" << pid << "/mountinfo";
    std::ifstream input(path.str());

    std::map<int, MountInfo> mounts;
    std::string line;
    while (std::getline(input, line)) {
        std::vector<std::string> fields = split_fields(line);
        if (fields.size() < 6) {
            continue;
        }
        std::optional<int> id = parse_int(fields[0]);
        if (!id) {
            continue;
        }
        MountInfo info;
        info.root = decode_mount_field(fields[3]);
        info.mount_point = decode_mount_field(fields[4]);
        auto sep = std::find(fields.begin(), fields.end(), "-");
        if (sep != fields.end() && sep + 1 != fields.end()) {
            info.fs_type = *(sep + 1);
        }
        mounts[*id] = info;
    }
    return mounts;
}

void attach_mount_info(const std::map<int, MountInfo>& mounts, FdEntry* entry) {
    if (!entry->mnt_id) {
        return;
    }
    auto it = mounts.find(*entry->mnt_id);
    if (it == mounts.end()) {
        return;
    }
    entry->mount_root = it->second.root;
    entry->mount_point = it->second.mount_point;
}

void read_fdinfo(int pid, FdEntry* entry) {
    std::ostringstream path;
    path << "/proc/" << pid << "/fdinfo/" << entry->fd;
    std::ifstream input(path.str());
    if (!input) {
        return;
    }

    std::string line;
    while (std::getline(input, line)) {
        if (starts_with(line, "pos:")) {
            entry->pos = parse_unsigned(value_after_colon(line));
        } else if (starts_with(line, "flags:")) {
            entry->fdinfo_flags = parse_int(value_after_colon(line), 8);
        } else if (starts_with(line, "mnt_id:")) {
            entry->mnt_id = parse_int(value_after_colon(line));
        } else if (starts_with(line, "ino:")) {
            entry->fdinfo_inode = parse_unsigned(value_after_colon(line));
        } else if (starts_with(line, "tfd:")) {
            EpollTarget target;
            std::optional<int> fd = parse_int(token_after(line, "tfd"));
            if (fd) {
                target.fd = *fd;
            }
            target.events = token_after(line, "events");
            target.data = token_after(line, "data");
            entry->epoll_targets.push_back(target);
        } else if (starts_with(line, "eventfd-count:")) {
            entry->eventfd_count = parse_unsigned(value_after_colon(line));
        } else if (starts_with(line, "eventfd-id:")) {
            entry->eventfd_id = parse_unsigned(value_after_colon(line));
        } else if (starts_with(line, "clockid:")) {
            entry->timerfd_clockid = parse_int(value_after_colon(line));
        } else if (starts_with(line, "ticks:")) {
            entry->timerfd_ticks = parse_unsigned(value_after_colon(line));
        } else if (starts_with(line, "sigmask:")) {
            entry->signal_mask = value_after_colon(line);
        } else if (starts_with(line, "inotify ")) {
            InotifyWatch watch;
            std::optional<int> wd = parse_int(token_after(line, "wd:"));
            if (wd) {
                watch.wd = *wd;
            }
            std::optional<uint64_t> ino = parse_unsigned(token_after(line, "ino:"), 16);
            if (ino) {
                watch.inode = *ino;
            }
            watch.device = token_after(line, "sdev:");
            watch.mask = token_after(line, "mask:");
            watch.ignored_mask = token_after(line, "ignored_mask:");
            watch.file_handle = token_after(line, "fhandle-bytes:");
            entry->inotify_watches.push_back(std::move(watch));
            if (entry->type == FdType::AnonOther || entry->type == FdType::Unknown) {
                entry->type = FdType::Inotify;
            }
        } else if (starts_with(line, "fanotify ")) {
            FanotifyMark mark;
            mark.mnt_id = parse_int(token_after(line, "mnt_id:"));
            std::optional<uint64_t> ino = parse_unsigned(token_after(line, "ino:"), 16);
            if (ino) {
                mark.inode = *ino;
            }
            mark.device = token_after(line, "sdev:");
            mark.mark_flags = token_after(line, "mflags:");
            mark.mask = token_after(line, "mask:");
            mark.ignored_mask = token_after(line, "ignored_mask:");
            mark.file_handle = token_after(line, "fhandle-bytes:");
            if (!mark.mnt_id && mark.inode == 0 && mark.device.empty() && mark.mask.empty()) {
                continue;
            }
            entry->fanotify_marks.push_back(std::move(mark));
            if (entry->type == FdType::AnonOther || entry->type == FdType::Unknown) {
                entry->type = FdType::Fanotify;
            }
        }
    }
}

}  // namespace fdi::detail
