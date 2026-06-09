#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <thread>
#include <unistd.h>
#include <vector>

int parse_count(int argc, char** argv) {
    if (argc < 2) {
        return 512;
    }
    char* end = nullptr;
    long value = std::strtol(argv[1], &end, 10);
    if (!argv[1][0] || (end && *end != '\0') || value <= 0 || value > 20000) {
        return 512;
    }
    return static_cast<int>(value);
}

int main(int argc, char** argv) {
    int count = parse_count(argc, argv);
    std::vector<int> held_fds;
    held_fds.reserve(static_cast<size_t>(count));

    for (int i = 0; i < count; ++i) {
        int fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            std::cerr << "fd_many_demo: open failed after " << held_fds.size()
                      << " fd(s): " << std::strerror(errno) << '\n';
            break;
        }
        held_fds.push_back(fd);
    }

    std::cout << "fd_many_demo pid=" << getpid() << " held=" << held_fds.size() << '\n';
    std::cout << "Run: fd-inspector --pid " << getpid() << " --max-fd 0 --io-uring --json\n";
    std::cout.flush();

    std::this_thread::sleep_for(std::chrono::seconds(30));
    for (int fd : held_fds) {
        ::close(fd);
    }
    return 0;
}
