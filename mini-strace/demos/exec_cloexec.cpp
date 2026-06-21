#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <unistd.h>

namespace {

int parse_fd(const char* text) {
    char* end = nullptr;
    const long value = std::strtol(text, &end, 10);
    if (end == text || *end != '\0' || value < 0 || value > 1024 * 1024) {
        return -1;
    }
    return static_cast<int>(value);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "--after-exec") {
        const int fd = parse_fd(argv[2]);
        if (fd < 0) {
            return 2;
        }
        const char byte = 'x';
        errno = 0;
        const ssize_t written = ::write(fd, &byte, 1);
        return written == -1 && errno == EBADF ? 0 : 1;
    }

    const int fd = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return 1;
    }
    const std::string fd_arg = std::to_string(fd);
    ::execl(argv[0], argv[0], "--after-exec", fd_arg.c_str(), nullptr);
    return 127;
}
