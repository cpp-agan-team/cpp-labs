#include <fcntl.h>
#include <unistd.h>

int main() {
    const char msg[] = "file_ops\n";
    ::write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    const int fd = ::open("/definitely/not/here/mini-strace", O_RDONLY);
    if (fd >= 0) {
        ::close(fd);
    }
    return 0;
}
