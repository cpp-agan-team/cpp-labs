#include <cerrno>
#include <fcntl.h>
#include <linux/stat.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#ifndef SYS_close_range
#ifdef __NR_close_range
#define SYS_close_range __NR_close_range
#endif
#endif

int main() {
    struct statx stx {};
    if (::syscall(SYS_statx, AT_FDCWD, "/proc/self/exe", AT_SYMLINK_NOFOLLOW,
                  STATX_TYPE | STATX_SIZE, &stx) != 0) {
        return 1;
    }

    struct stat st {};
    if (::syscall(SYS_newfstatat, AT_FDCWD, "/proc/self/exe", &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return 2;
    }

    rlimit old_limit{};
    if (::syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, nullptr, &old_limit) != 0) {
        return 3;
    }

    std::thread worker([] {});
    worker.join();

    int pipefd[2] = {-1, -1};
    if (::pipe(pipefd) != 0) {
        return 4;
    }
#ifdef SYS_close_range
    errno = 0;
    const long close_range_rc = ::syscall(SYS_close_range, static_cast<unsigned int>(pipefd[0]),
                                          static_cast<unsigned int>(pipefd[0]), 0U);
    if (close_range_rc != 0 && errno != ENOSYS) {
        return 5;
    }
    if (close_range_rc != 0 && errno == ENOSYS) {
        ::close(pipefd[0]);
    }
#else
    ::close(pipefd[0]);
#endif
    ::close(pipefd[1]);

    const pid_t child = ::fork();
    if (child < 0) {
        return 6;
    }
    if (child == 0) {
        _exit(7);
    }

    int status = 0;
    const long waited = ::syscall(SYS_wait4, child, &status, 0, nullptr);
    if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 7) {
        return 8;
    }
    return 0;
}
