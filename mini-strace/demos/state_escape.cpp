#include <fcntl.h>
#include <string>
#include <unistd.h>

int main() {
    const std::string path =
        "/tmp/mini-strace-state-escape-\n-" + std::to_string(static_cast<long long>(::getpid()));
    const int fd = ::open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) {
        return 1;
    }

    const char byte = 'x';
    const bool ok = ::write(fd, &byte, 1) == 1;
    (void)::close(fd);
    (void)::unlink(path.c_str());
    return ok ? 0 : 1;
}
