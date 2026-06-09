#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <thread>

int main() {
    std::cout << "fd_exec_demo pid=" << getpid() << '\n';
    std::cout.flush();
    std::this_thread::sleep_for(std::chrono::seconds(2));

    int fd = ::open("/tmp/fd_exec_demo_file", O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        return 1;
    }

    char arg0[] = "sleep";
    char arg1[] = "3";
    char* argv[] = {arg0, arg1, nullptr};
    ::execvp("sleep", argv);
    return 1;
}
