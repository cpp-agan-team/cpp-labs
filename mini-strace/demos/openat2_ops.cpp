#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <unistd.h>

int main() {
    open_how how{};
    how.flags = O_RDONLY | O_CLOEXEC;
#ifdef RESOLVE_NO_MAGICLINKS
    how.resolve = RESOLVE_NO_MAGICLINKS;
#endif
    const int fd =
        static_cast<int>(::syscall(SYS_openat2, AT_FDCWD, "/dev/null", &how, sizeof(how)));
    if (fd < 0) {
        return 1;
    }
    return ::close(fd) == 0 ? 0 : 1;
}
