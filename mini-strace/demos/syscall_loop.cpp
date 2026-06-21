#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

long parse_count(const char* text) {
    char* end = nullptr;
    const long value = std::strtol(text, &end, 10);
    if (end == text || *end != '\0' || value <= 0) {
        return -1;
    }
    return value;
}

int run_getpid_loop(long count) {
    volatile long sink = 0;
    for (long i = 0; i < count; ++i) {
        sink += ::syscall(SYS_getpid);
    }
    return sink == 0 ? 1 : 0;
}

int run_write_loop(long count) {
    const int fd = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return 1;
    }
    const char byte = 'x';
    for (long i = 0; i < count; ++i) {
        ssize_t written = 0;
        do {
            written = ::write(fd, &byte, 1);
        } while (written < 0 && errno == EINTR);
        if (written != 1) {
            const int saved = errno;
            (void)::close(fd);
            errno = saved;
            return 1;
        }
    }
    return ::close(fd) == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    std::string syscall = "getpid";
    long count = 1000;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--syscall" && i + 1 < argc) {
            syscall = argv[++i];
            continue;
        }
        if (arg == "--count" && i + 1 < argc) {
            count = parse_count(argv[++i]);
            if (count <= 0) {
                return 2;
            }
            continue;
        }
        return 2;
    }

    if (syscall == "getpid") {
        return run_getpid_loop(count);
    }
    if (syscall == "write") {
        return run_write_loop(count);
    }
    return 2;
}
