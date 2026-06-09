#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

int main() {
    std::vector<int> held_fds;
    std::cout << "fd_leak_demo pid=" << getpid() << '\n';
    std::cout << "Run: fd-inspector --pid " << getpid() << " --leak-check 3\n";
    std::cout.flush();

    while (true) {
        int fd = ::open("/tmp/fd_leak_demo_file", O_CREAT | O_RDWR | O_CLOEXEC, 0600);
        if (fd >= 0) {
            held_fds.push_back(fd);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}
