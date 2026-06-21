#include "internal.hpp"

#include <cerrno>
#include <cstring>
#include <sstream>
#include <string>
#include <sys/syscall.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mini_strace {
namespace {

struct SyscallPair {
    std::uint64_t nr;
    const char* name;
};

std::vector<SyscallPair> build_syscalls() {
    std::vector<SyscallPair> items;
#define MINI_STRACE_ADD_SYSCALL(name)                                     \
    do {                                                                  \
        items.push_back({static_cast<std::uint64_t>(SYS_##name), #name}); \
    } while (false)

#ifdef SYS_read
    MINI_STRACE_ADD_SYSCALL(read);
#endif
#ifdef SYS_write
    MINI_STRACE_ADD_SYSCALL(write);
#endif
#ifdef SYS_open
    MINI_STRACE_ADD_SYSCALL(open);
#endif
#ifdef SYS_close
    MINI_STRACE_ADD_SYSCALL(close);
#endif
#ifdef SYS_stat
    MINI_STRACE_ADD_SYSCALL(stat);
#endif
#ifdef SYS_fstat
    MINI_STRACE_ADD_SYSCALL(fstat);
#endif
#ifdef SYS_lstat
    MINI_STRACE_ADD_SYSCALL(lstat);
#endif
#ifdef SYS_poll
    MINI_STRACE_ADD_SYSCALL(poll);
#endif
#ifdef SYS_ppoll
    MINI_STRACE_ADD_SYSCALL(ppoll);
#endif
#ifdef SYS_lseek
    MINI_STRACE_ADD_SYSCALL(lseek);
#endif
#ifdef SYS_mmap
    MINI_STRACE_ADD_SYSCALL(mmap);
#endif
#ifdef SYS_mprotect
    MINI_STRACE_ADD_SYSCALL(mprotect);
#endif
#ifdef SYS_munmap
    MINI_STRACE_ADD_SYSCALL(munmap);
#endif
#ifdef SYS_brk
    MINI_STRACE_ADD_SYSCALL(brk);
#endif
#ifdef SYS_rt_sigaction
    MINI_STRACE_ADD_SYSCALL(rt_sigaction);
#endif
#ifdef SYS_rt_sigprocmask
    MINI_STRACE_ADD_SYSCALL(rt_sigprocmask);
#endif
#ifdef SYS_ioctl
    MINI_STRACE_ADD_SYSCALL(ioctl);
#endif
#ifdef SYS_pread64
    MINI_STRACE_ADD_SYSCALL(pread64);
#endif
#ifdef SYS_pwrite64
    MINI_STRACE_ADD_SYSCALL(pwrite64);
#endif
#ifdef SYS_readv
    MINI_STRACE_ADD_SYSCALL(readv);
#endif
#ifdef SYS_writev
    MINI_STRACE_ADD_SYSCALL(writev);
#endif
#ifdef SYS_access
    MINI_STRACE_ADD_SYSCALL(access);
#endif
#ifdef SYS_pipe
    MINI_STRACE_ADD_SYSCALL(pipe);
#endif
#ifdef SYS_select
    MINI_STRACE_ADD_SYSCALL(select);
#endif
#ifdef SYS_sched_yield
    MINI_STRACE_ADD_SYSCALL(sched_yield);
#endif
#ifdef SYS_mremap
    MINI_STRACE_ADD_SYSCALL(mremap);
#endif
#ifdef SYS_msync
    MINI_STRACE_ADD_SYSCALL(msync);
#endif
#ifdef SYS_mincore
    MINI_STRACE_ADD_SYSCALL(mincore);
#endif
#ifdef SYS_madvise
    MINI_STRACE_ADD_SYSCALL(madvise);
#endif
#ifdef SYS_dup
    MINI_STRACE_ADD_SYSCALL(dup);
#endif
#ifdef SYS_dup2
    MINI_STRACE_ADD_SYSCALL(dup2);
#endif
#ifdef SYS_pause
    MINI_STRACE_ADD_SYSCALL(pause);
#endif
#ifdef SYS_nanosleep
    MINI_STRACE_ADD_SYSCALL(nanosleep);
#endif
#ifdef SYS_restart_syscall
    MINI_STRACE_ADD_SYSCALL(restart_syscall);
#endif
#ifdef SYS_getpid
    MINI_STRACE_ADD_SYSCALL(getpid);
#endif
#ifdef SYS_socket
    MINI_STRACE_ADD_SYSCALL(socket);
#endif
#ifdef SYS_socketpair
    MINI_STRACE_ADD_SYSCALL(socketpair);
#endif
#ifdef SYS_connect
    MINI_STRACE_ADD_SYSCALL(connect);
#endif
#ifdef SYS_accept
    MINI_STRACE_ADD_SYSCALL(accept);
#endif
#ifdef SYS_sendto
    MINI_STRACE_ADD_SYSCALL(sendto);
#endif
#ifdef SYS_recvfrom
    MINI_STRACE_ADD_SYSCALL(recvfrom);
#endif
#ifdef SYS_sendmsg
    MINI_STRACE_ADD_SYSCALL(sendmsg);
#endif
#ifdef SYS_recvmsg
    MINI_STRACE_ADD_SYSCALL(recvmsg);
#endif
#ifdef SYS_bind
    MINI_STRACE_ADD_SYSCALL(bind);
#endif
#ifdef SYS_listen
    MINI_STRACE_ADD_SYSCALL(listen);
#endif
#ifdef SYS_setsockopt
    MINI_STRACE_ADD_SYSCALL(setsockopt);
#endif
#ifdef SYS_getsockopt
    MINI_STRACE_ADD_SYSCALL(getsockopt);
#endif
#ifdef SYS_clone
    MINI_STRACE_ADD_SYSCALL(clone);
#endif
#ifdef SYS_fork
    MINI_STRACE_ADD_SYSCALL(fork);
#endif
#ifdef SYS_vfork
    MINI_STRACE_ADD_SYSCALL(vfork);
#endif
#ifdef SYS_execve
    MINI_STRACE_ADD_SYSCALL(execve);
#endif
#ifdef SYS_exit
    MINI_STRACE_ADD_SYSCALL(exit);
#endif
#ifdef SYS_wait4
    MINI_STRACE_ADD_SYSCALL(wait4);
#endif
#ifdef SYS_kill
    MINI_STRACE_ADD_SYSCALL(kill);
#endif
#ifdef SYS_fcntl
    MINI_STRACE_ADD_SYSCALL(fcntl);
#endif
#ifdef SYS_fsync
    MINI_STRACE_ADD_SYSCALL(fsync);
#endif
#ifdef SYS_fdatasync
    MINI_STRACE_ADD_SYSCALL(fdatasync);
#endif
#ifdef SYS_truncate
    MINI_STRACE_ADD_SYSCALL(truncate);
#endif
#ifdef SYS_ftruncate
    MINI_STRACE_ADD_SYSCALL(ftruncate);
#endif
#ifdef SYS_getcwd
    MINI_STRACE_ADD_SYSCALL(getcwd);
#endif
#ifdef SYS_chdir
    MINI_STRACE_ADD_SYSCALL(chdir);
#endif
#ifdef SYS_rename
    MINI_STRACE_ADD_SYSCALL(rename);
#endif
#ifdef SYS_mkdir
    MINI_STRACE_ADD_SYSCALL(mkdir);
#endif
#ifdef SYS_rmdir
    MINI_STRACE_ADD_SYSCALL(rmdir);
#endif
#ifdef SYS_creat
    MINI_STRACE_ADD_SYSCALL(creat);
#endif
#ifdef SYS_link
    MINI_STRACE_ADD_SYSCALL(link);
#endif
#ifdef SYS_unlink
    MINI_STRACE_ADD_SYSCALL(unlink);
#endif
#ifdef SYS_symlink
    MINI_STRACE_ADD_SYSCALL(symlink);
#endif
#ifdef SYS_readlink
    MINI_STRACE_ADD_SYSCALL(readlink);
#endif
#ifdef SYS_chmod
    MINI_STRACE_ADD_SYSCALL(chmod);
#endif
#ifdef SYS_fchmod
    MINI_STRACE_ADD_SYSCALL(fchmod);
#endif
#ifdef SYS_chown
    MINI_STRACE_ADD_SYSCALL(chown);
#endif
#ifdef SYS_fchown
    MINI_STRACE_ADD_SYSCALL(fchown);
#endif
#ifdef SYS_umask
    MINI_STRACE_ADD_SYSCALL(umask);
#endif
#ifdef SYS_gettimeofday
    MINI_STRACE_ADD_SYSCALL(gettimeofday);
#endif
#ifdef SYS_getrlimit
    MINI_STRACE_ADD_SYSCALL(getrlimit);
#endif
#ifdef SYS_getrusage
    MINI_STRACE_ADD_SYSCALL(getrusage);
#endif
#ifdef SYS_getuid
    MINI_STRACE_ADD_SYSCALL(getuid);
#endif
#ifdef SYS_getgid
    MINI_STRACE_ADD_SYSCALL(getgid);
#endif
#ifdef SYS_geteuid
    MINI_STRACE_ADD_SYSCALL(geteuid);
#endif
#ifdef SYS_getegid
    MINI_STRACE_ADD_SYSCALL(getegid);
#endif
#ifdef SYS_getppid
    MINI_STRACE_ADD_SYSCALL(getppid);
#endif
#ifdef SYS_gettid
    MINI_STRACE_ADD_SYSCALL(gettid);
#endif
#ifdef SYS_futex
    MINI_STRACE_ADD_SYSCALL(futex);
#endif
#ifdef SYS_prctl
    MINI_STRACE_ADD_SYSCALL(prctl);
#endif
#ifdef SYS_sched_getaffinity
    MINI_STRACE_ADD_SYSCALL(sched_getaffinity);
#endif
#ifdef SYS_set_tid_address
    MINI_STRACE_ADD_SYSCALL(set_tid_address);
#endif
#ifdef SYS_clock_gettime
    MINI_STRACE_ADD_SYSCALL(clock_gettime);
#endif
#ifdef SYS_exit_group
    MINI_STRACE_ADD_SYSCALL(exit_group);
#endif
#ifdef SYS_epoll_wait
    MINI_STRACE_ADD_SYSCALL(epoll_wait);
#endif
#ifdef SYS_epoll_ctl
    MINI_STRACE_ADD_SYSCALL(epoll_ctl);
#endif
#ifdef SYS_epoll_create
    MINI_STRACE_ADD_SYSCALL(epoll_create);
#endif
#ifdef SYS_epoll_create1
    MINI_STRACE_ADD_SYSCALL(epoll_create1);
#endif
#ifdef SYS_epoll_pwait
    MINI_STRACE_ADD_SYSCALL(epoll_pwait);
#endif
#ifdef SYS_openat
    MINI_STRACE_ADD_SYSCALL(openat);
#endif
#ifdef SYS_newfstatat
    MINI_STRACE_ADD_SYSCALL(newfstatat);
#endif
#ifdef SYS_accept4
    MINI_STRACE_ADD_SYSCALL(accept4);
#endif
#ifdef SYS_pipe2
    MINI_STRACE_ADD_SYSCALL(pipe2);
#endif
#ifdef SYS_dup3
    MINI_STRACE_ADD_SYSCALL(dup3);
#endif
#ifdef SYS_prlimit64
    MINI_STRACE_ADD_SYSCALL(prlimit64);
#endif
#ifdef SYS_getrandom
    MINI_STRACE_ADD_SYSCALL(getrandom);
#endif
#ifdef SYS_memfd_create
    MINI_STRACE_ADD_SYSCALL(memfd_create);
#endif
#ifdef SYS_execveat
    MINI_STRACE_ADD_SYSCALL(execveat);
#endif
#ifdef SYS_statx
    MINI_STRACE_ADD_SYSCALL(statx);
#endif
#ifdef SYS_clone3
    MINI_STRACE_ADD_SYSCALL(clone3);
#endif
#ifdef SYS_openat2
    MINI_STRACE_ADD_SYSCALL(openat2);
#endif
#ifdef SYS_close_range
    MINI_STRACE_ADD_SYSCALL(close_range);
#endif

#undef MINI_STRACE_ADD_SYSCALL
    return items;
}

const std::unordered_map<std::uint64_t, std::string>& nr_to_name() {
    static const std::unordered_map<std::uint64_t, std::string> table = [] {
        std::unordered_map<std::uint64_t, std::string> result;
        for (const auto& item : build_syscalls()) {
            result.emplace(item.nr, item.name);
        }
        return result;
    }();
    return table;
}

const std::unordered_map<std::string, std::uint64_t>& name_to_nr() {
    static const std::unordered_map<std::string, std::uint64_t> table = [] {
        std::unordered_map<std::string, std::uint64_t> result;
        for (const auto& item : build_syscalls()) {
            result.emplace(item.name, item.nr);
        }
        return result;
    }();
    return table;
}

}  // namespace

std::string syscall_name(std::uint64_t nr) {
    const auto& table = nr_to_name();
    const auto it = table.find(nr);
    if (it != table.end()) {
        return it->second;
    }
    return "sys_" + std::to_string(nr);
}

bool syscall_number_by_name(const std::string& name, std::uint64_t& nr) {
    const auto& table = name_to_nr();
    const auto it = table.find(name);
    if (it == table.end()) {
        return false;
    }
    nr = it->second;
    return true;
}

std::string errno_name(int value) {
    switch (value) {
        case EPERM:
            return "EPERM";
        case ENOENT:
            return "ENOENT";
        case ESRCH:
            return "ESRCH";
        case EINTR:
            return "EINTR";
        case EIO:
            return "EIO";
        case ENXIO:
            return "ENXIO";
        case E2BIG:
            return "E2BIG";
        case ENOEXEC:
            return "ENOEXEC";
        case EBADF:
            return "EBADF";
        case ECHILD:
            return "ECHILD";
        case EAGAIN:
            return "EAGAIN";
        case ENOMEM:
            return "ENOMEM";
        case EACCES:
            return "EACCES";
        case EFAULT:
            return "EFAULT";
        case EBUSY:
            return "EBUSY";
        case EEXIST:
            return "EEXIST";
        case EXDEV:
            return "EXDEV";
        case ENODEV:
            return "ENODEV";
        case ENOTDIR:
            return "ENOTDIR";
        case EISDIR:
            return "EISDIR";
        case EINVAL:
            return "EINVAL";
        case ENFILE:
            return "ENFILE";
        case EMFILE:
            return "EMFILE";
        case ENOTTY:
            return "ENOTTY";
        case ETXTBSY:
            return "ETXTBSY";
        case EFBIG:
            return "EFBIG";
        case ENOSPC:
            return "ENOSPC";
        case ESPIPE:
            return "ESPIPE";
        case EROFS:
            return "EROFS";
        case EMLINK:
            return "EMLINK";
        case EPIPE:
            return "EPIPE";
        case EDOM:
            return "EDOM";
        case ERANGE:
            return "ERANGE";
        case ENOSYS:
            return "ENOSYS";
        case ETIMEDOUT:
            return "ETIMEDOUT";
        case ECONNREFUSED:
            return "ECONNREFUSED";
        case ECONNRESET:
            return "ECONNRESET";
        case ENOTCONN:
            return "ENOTCONN";
        case EADDRINUSE:
            return "EADDRINUSE";
        case EADDRNOTAVAIL:
            return "EADDRNOTAVAIL";
        default:
            return "ERRNO_" + std::to_string(value);
    }
}

namespace detail {

std::string format_errno_message(int value) {
    const char* message = std::strerror(value);
    if (message == nullptr) {
        return {};
    }
    return message;
}

std::string format_operation_error(const std::string& operation, int error) {
    const int value = error == 0 ? EIO : error;
    std::ostringstream out;
    out << operation << " failed: " << format_errno_message(value)
        << " (errno=" << errno_name(value) << '/' << value << ')';
    return out.str();
}

}  // namespace detail
}  // namespace mini_strace
