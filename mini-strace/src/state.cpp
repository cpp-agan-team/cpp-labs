#include "internal.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <linux/openat2.h>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE (1U << 1)
#endif

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

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

std::string strip_quotes(std::string value) {
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.size() - 2);
    } else if (value.size() >= 4 && value.front() == '"' &&
               value.substr(value.size() - 4) == "...\"") {
        value = value.substr(1, value.size() - 5);
    }
    return value;
}

bool syscall_succeeded(const SyscallEvent& event) {
    return !event.is_error && event.raw_ret >= 0;
}

int first_fd_arg(const SyscallEvent& event) {
    if (event.raw_args.empty()) {
        return -1;
    }
    return static_cast<int>(event.raw_args[0]);
}

std::string perms_from_prot(std::uint64_t prot) {
    std::string perms;
    perms.push_back((prot & PROT_READ) != 0 ? 'r' : '-');
    perms.push_back((prot & PROT_WRITE) != 0 ? 'w' : '-');
    perms.push_back((prot & PROT_EXEC) != 0 ? 'x' : '-');
    return perms;
}

std::string source_from_mmap(const SyscallEvent& event,
                             const std::unordered_map<int, FdContext>& fds) {
    const int fd = static_cast<int>(event.raw_args[4]);
    if (fd < 0) {
        return "anon";
    }
    const auto it = fds.find(fd);
    if (it != fds.end() && !it->second.path.empty()) {
        return it->second.path;
    }
    return "fd:" + std::to_string(fd);
}

bool flags_have_cloexec(std::uint64_t flags) {
#ifdef O_CLOEXEC
    return (flags & static_cast<std::uint64_t>(O_CLOEXEC)) != 0;
#else
    (void)flags;
    return false;
#endif
}

std::optional<std::uint64_t> read_openat2_flags(pid_t pid, std::uint64_t address,
                                                std::uint64_t size) {
    if (address == 0 || size < sizeof(std::uint64_t)) {
        return std::nullopt;
    }
    const std::size_t read_len =
        static_cast<std::size_t>(std::min<std::uint64_t>(size, sizeof(open_how)));
    const auto bytes = read_remote_bytes(pid, address, read_len);
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.size() < sizeof(std::uint64_t)) {
        return std::nullopt;
    }
    open_how how{};
    std::memcpy(&how, bytes.data.data(), std::min(bytes.data.size(), sizeof(how)));
    return how.flags;
}

std::optional<std::array<int, 2>> read_fd_pair(pid_t pid, std::uint64_t address) {
    const auto bytes = read_remote_bytes(pid, address, sizeof(int) * 2);
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.size() < sizeof(int) * 2) {
        return std::nullopt;
    }
    std::array<int, 2> fds{};
    std::memcpy(fds.data(), bytes.data.data(), sizeof(int) * 2);
    return fds;
}

FdContext pipe_context(int fd, int peer, bool close_on_exec, std::string source) {
    FdContext ctx;
    ctx.fd = fd;
    ctx.kind = "pipe";
    ctx.path = "pipe";
    ctx.peer = "fd:" + std::to_string(peer);
    ctx.close_on_exec = close_on_exec;
    ctx.known = true;
    ctx.source = std::move(source);
    return ctx;
}

FdContext socketpair_context(int fd, int peer, bool close_on_exec) {
    FdContext ctx;
    ctx.fd = fd;
    ctx.kind = "socket";
    ctx.path = "socketpair";
    ctx.peer = "fd:" + std::to_string(peer);
    ctx.close_on_exec = close_on_exec;
    ctx.known = true;
    ctx.source = "socketpair";
    return ctx;
}

bool is_fcntl_dup(std::uint64_t command) {
    switch (static_cast<int>(command)) {
#ifdef F_DUPFD
        case F_DUPFD:
            return true;
#endif
#ifdef F_DUPFD_CLOEXEC
        case F_DUPFD_CLOEXEC:
            return true;
#endif
        default:
            return false;
    }
}

bool fcntl_sets_cloexec(std::uint64_t command) {
#ifdef F_DUPFD_CLOEXEC
    return static_cast<int>(command) == F_DUPFD_CLOEXEC;
#else
    (void)command;
    return false;
#endif
}

bool is_fcntl_setfd(std::uint64_t command) {
#ifdef F_SETFD
    return static_cast<int>(command) == F_SETFD;
#else
    (void)command;
    return false;
#endif
}

bool fd_flags_have_cloexec(std::uint64_t flags) {
#ifdef FD_CLOEXEC
    return (flags & static_cast<std::uint64_t>(FD_CLOEXEC)) != 0;
#else
    (void)flags;
    return false;
#endif
}

bool close_range_marks_cloexec(std::uint64_t flags) {
    return (flags & static_cast<std::uint64_t>(CLOSE_RANGE_CLOEXEC)) != 0;
}

std::string fcntl_source(std::uint64_t command) {
    switch (static_cast<int>(command)) {
#ifdef F_DUPFD
        case F_DUPFD:
            return "fcntl:F_DUPFD";
#endif
#ifdef F_DUPFD_CLOEXEC
        case F_DUPFD_CLOEXEC:
            return "fcntl:F_DUPFD_CLOEXEC";
#endif
        default:
            return "fcntl";
    }
}

}  // namespace

void StateTracker::seed_from_proc(pid_t pid) {
    const std::filesystem::path fd_dir =
        std::filesystem::path("/proc") / std::to_string(pid) / "fd";
    std::error_code ec;
    if (!std::filesystem::exists(fd_dir, ec)) {
        return;
    }
    for (const auto& entry : std::filesystem::directory_iterator(fd_dir, ec)) {
        if (ec) {
            break;
        }
        const std::string name = entry.path().filename().string();
        char* end = nullptr;
        const long fd_long = std::strtol(name.c_str(), &end, 10);
        if (end == name.c_str() || *end != '\0' || fd_long < 0) {
            continue;
        }
        std::array<char, 4096> buffer{};
        const ssize_t nread = ::readlink(entry.path().c_str(), buffer.data(), buffer.size() - 1);
        if (nread < 0) {
            continue;
        }
        buffer[static_cast<std::size_t>(nread)] = '\0';
        FdContext ctx;
        ctx.fd = static_cast<int>(fd_long);
        ctx.path = buffer.data();
        ctx.known = true;
        ctx.source = "proc";
        if (ctx.path.rfind("socket:", 0) == 0) {
            ctx.kind = "socket";
        } else if (ctx.path.rfind("pipe:", 0) == 0) {
            ctx.kind = "pipe";
        } else {
            ctx.kind = "file";
        }
        fds_[ctx.fd] = ctx;
    }
}

void StateTracker::on_exec() {
    for (auto it = fds_.begin(); it != fds_.end();) {
        if (it->second.close_on_exec) {
            it = fds_.erase(it);
        } else {
            ++it;
        }
    }
}

void StateTracker::enrich_before(SyscallEvent& event) const {
    const std::string& name = event.name;
    if (name == "read" || name == "write" || name == "close" || name == "connect" ||
        name == "bind" || name == "listen" || name == "accept" || name == "accept4" ||
        name == "sendto" || name == "recvfrom" || name == "sendmsg" || name == "recvmsg" ||
        name == "setsockopt" || name == "getsockopt" || name == "fsync" || name == "fdatasync" ||
        name == "fcntl") {
        const int fd = first_fd_arg(event);
        const auto it = fds_.find(fd);
        if (it != fds_.end()) {
            event.fd_context = it->second;
        }
    }
}

void StateTracker::apply(SyscallEvent& event) {
    const std::string& name = event.name;
    if (syscall_succeeded(event) &&
        (name == "open" || name == "openat" || name == "creat" || name == "openat2")) {
        const int fd = static_cast<int>(event.raw_ret);
        FdContext ctx;
        ctx.fd = fd;
        ctx.kind = "file";
        if (const auto path = arg_value(event, "pathname")) {
            ctx.path = strip_quotes(*path);
        }
        if (name == "open" || name == "openat") {
            const std::size_t flags_index = name == "openat" ? 2 : 1;
            ctx.close_on_exec = flags_have_cloexec(event.raw_args[flags_index]);
        } else if (name == "openat2") {
            if (const auto flags =
                    read_openat2_flags(event.tid, event.raw_args[2], event.raw_args[3])) {
                ctx.close_on_exec = flags_have_cloexec(*flags);
            }
        }
        ctx.known = true;
        ctx.source = "syscall";
        fds_[fd] = ctx;
        event.fd_context = ctx;
        return;
    }
    if (syscall_succeeded(event) && name == "close") {
        fds_.erase(first_fd_arg(event));
        return;
    }
    if (syscall_succeeded(event) && name == "close_range") {
        const auto first = event.raw_args[0];
        const auto last = event.raw_args[1];
        const bool mark_cloexec = close_range_marks_cloexec(event.raw_args[2]);
        for (auto it = fds_.begin(); it != fds_.end();) {
            const auto fd = static_cast<std::uint64_t>(it->first);
            if (fd < first || fd > last) {
                ++it;
                continue;
            }
            if (mark_cloexec) {
                it->second.close_on_exec = true;
                it->second.source = "close_range:CLOEXEC";
                ++it;
            } else {
                it = fds_.erase(it);
            }
        }
        return;
    }
    if (syscall_succeeded(event) && name == "dup") {
        const int oldfd = static_cast<int>(event.raw_args[0]);
        const int newfd = static_cast<int>(event.raw_ret);
        auto it = fds_.find(oldfd);
        if (it != fds_.end()) {
            FdContext ctx = it->second;
            ctx.fd = newfd;
            ctx.source = "dup";
            fds_[newfd] = ctx;
            event.fd_context = ctx;
        }
        return;
    }
    if (syscall_succeeded(event) && (name == "dup2" || name == "dup3")) {
        const int oldfd = static_cast<int>(event.raw_args[0]);
        const int newfd = static_cast<int>(event.raw_args[1]);
        auto it = fds_.find(oldfd);
        if (it != fds_.end()) {
            FdContext ctx = it->second;
            ctx.fd = newfd;
            ctx.source = name;
            if (name == "dup3") {
                ctx.close_on_exec = flags_have_cloexec(event.raw_args[2]);
            } else {
                ctx.close_on_exec = false;
            }
            fds_[newfd] = ctx;
            event.fd_context = ctx;
        }
        return;
    }
    if (syscall_succeeded(event) && name == "socket") {
        FdContext ctx;
        ctx.fd = static_cast<int>(event.raw_ret);
        ctx.kind = "socket";
        ctx.path = "socket";
        ctx.known = true;
        ctx.source = "syscall";
        fds_[ctx.fd] = ctx;
        event.fd_context = ctx;
        return;
    }
    if (syscall_succeeded(event) && (name == "pipe" || name == "pipe2")) {
        const auto fds = read_fd_pair(event.tid, event.raw_args[0]);
        if (fds) {
            const bool close_on_exec =
                name == "pipe2" &&
                ((event.raw_args[1] & static_cast<std::uint64_t>(O_CLOEXEC)) != 0);
            FdContext read_end = pipe_context((*fds)[0], (*fds)[1], close_on_exec, name);
            FdContext write_end = pipe_context((*fds)[1], (*fds)[0], close_on_exec, name);
            fds_[read_end.fd] = read_end;
            fds_[write_end.fd] = write_end;
            event.fd_context = read_end;
        }
        return;
    }
    if (syscall_succeeded(event) && name == "socketpair") {
        const auto fds = read_fd_pair(event.tid, event.raw_args[3]);
        if (fds) {
            bool close_on_exec = false;
#ifdef SOCK_CLOEXEC
            close_on_exec = (event.raw_args[1] & static_cast<std::uint64_t>(SOCK_CLOEXEC)) != 0;
#endif
            FdContext first = socketpair_context((*fds)[0], (*fds)[1], close_on_exec);
            FdContext second = socketpair_context((*fds)[1], (*fds)[0], close_on_exec);
            fds_[first.fd] = first;
            fds_[second.fd] = second;
            event.fd_context = first;
        }
        return;
    }
    if (syscall_succeeded(event) && name == "connect") {
        const int fd = first_fd_arg(event);
        auto& ctx = fds_[fd];
        ctx.fd = fd;
        ctx.kind = "socket";
        ctx.known = true;
        ctx.source = "connect";
        if (const auto peer = arg_value(event, "addr")) {
            ctx.peer = *peer;
        }
        event.fd_context = ctx;
        return;
    }
    if (syscall_succeeded(event) && (name == "accept" || name == "accept4")) {
        FdContext ctx;
        ctx.fd = static_cast<int>(event.raw_ret);
        ctx.kind = "socket";
        ctx.path = "socket";
        ctx.known = true;
        ctx.source = name;
        if (const auto peer = arg_value(event, "addr")) {
            if (*peer != "NULL" && peer->rfind("0x", 0) != 0) {
                ctx.peer = *peer;
            }
        }
        fds_[ctx.fd] = ctx;
        event.fd_context = ctx;
        return;
    }
    if (syscall_succeeded(event) && name == "fcntl" && is_fcntl_dup(event.raw_args[1])) {
        const int oldfd = static_cast<int>(event.raw_args[0]);
        const int newfd = static_cast<int>(event.raw_ret);
        FdContext ctx;
        const auto it = fds_.find(oldfd);
        if (it != fds_.end()) {
            ctx = it->second;
        } else {
            ctx.kind = "fd";
            ctx.path = "fd:" + std::to_string(oldfd);
            ctx.known = false;
        }
        ctx.fd = newfd;
        ctx.close_on_exec = fcntl_sets_cloexec(event.raw_args[1]);
        ctx.source = fcntl_source(event.raw_args[1]);
        fds_[newfd] = ctx;
        event.fd_context = ctx;
        return;
    }
    if (syscall_succeeded(event) && name == "fcntl" && is_fcntl_setfd(event.raw_args[1])) {
        const int fd = static_cast<int>(event.raw_args[0]);
        auto it = fds_.find(fd);
        if (it != fds_.end()) {
            it->second.close_on_exec = fd_flags_have_cloexec(event.raw_args[2]);
            it->second.source = "fcntl:F_SETFD";
            event.fd_context = it->second;
        }
        return;
    }
    if (syscall_succeeded(event) && (name == "mmap")) {
        const auto begin = static_cast<std::uint64_t>(event.raw_ret);
        const auto length = event.raw_args[1];
        VmaContext ctx;
        ctx.begin = begin;
        ctx.end = begin + length;
        ctx.perms = perms_from_prot(event.raw_args[2]);
        ctx.source = source_from_mmap(event, fds_);
        ctx.known = true;
        vmas_.push_back(ctx);
        event.vma_context = ctx;
        return;
    }
    if (syscall_succeeded(event) && name == "munmap") {
        const auto begin = event.raw_args[0];
        const auto length = event.raw_args[1];
        const auto end = begin + length;
        vmas_.erase(std::remove_if(vmas_.begin(), vmas_.end(),
                                   [&](const VmaContext& ctx) {
                                       return !(ctx.end <= begin || ctx.begin >= end);
                                   }),
                    vmas_.end());
        VmaContext ctx;
        ctx.begin = begin;
        ctx.end = end;
        ctx.source = "unmapped";
        ctx.known = true;
        event.vma_context = ctx;
        return;
    }
    if (syscall_succeeded(event) && name == "mprotect") {
        const auto begin = event.raw_args[0];
        const auto length = event.raw_args[1];
        const auto end = begin + length;
        VmaContext ctx;
        ctx.begin = begin;
        ctx.end = end;
        ctx.perms = perms_from_prot(event.raw_args[2]);
        ctx.source = "perms";
        ctx.known = true;
        event.vma_context = ctx;
        return;
    }
    if (syscall_succeeded(event) && name == "brk") {
        current_brk_ = static_cast<std::uint64_t>(event.raw_ret);
        VmaContext ctx;
        ctx.begin = current_brk_;
        ctx.end = current_brk_;
        ctx.source = "heap-brk";
        ctx.known = true;
        event.vma_context = ctx;
        return;
    }
}

}  // namespace detail
}  // namespace mini_strace
