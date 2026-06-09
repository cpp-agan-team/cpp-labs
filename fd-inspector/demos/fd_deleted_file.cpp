#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>

int main() {
    char path[] = "/tmp/fd-deleted-file-XXXXXX";
    int fd = ::mkstemp(path);
    if (fd < 0) {
        std::cerr << "fd_deleted_file_demo: mkstemp failed: " << std::strerror(errno) << '\n';
        return 1;
    }

    std::string block(1024 * 1024, 'x');
    for (int i = 0; i < 8; ++i) {
        if (::write(fd, block.data(), block.size()) != static_cast<ssize_t>(block.size())) {
            std::cerr << "fd_deleted_file_demo: write failed: " << std::strerror(errno) << '\n';
            ::close(fd);
            return 1;
        }
    }
    ::fsync(fd);

    if (::unlink(path) != 0) {
        std::cerr << "fd_deleted_file_demo: unlink failed: " << std::strerror(errno) << '\n';
        ::close(fd);
        return 1;
    }

    std::cout << "fd_deleted_file_demo pid=" << getpid() << '\n';
    std::cout << "held_deleted_file_size=8388608\n";
    std::cout << "Run: fd-inspector --pid " << getpid()
              << " --json | jq '.[] | select(.deleted)'\n";
    std::cout.flush();

    std::this_thread::sleep_for(std::chrono::seconds(30));
    ::close(fd);
    return 0;
}
