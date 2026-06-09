#include <chrono>
#include <fcntl.h>
#include <iostream>
#include <linux/io_uring.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <thread>
#include <unistd.h>
#include <vector>

int main() {
    std::vector<int> held_fds;
    std::cout << "fd_sources_demo pid=" << getpid() << '\n';
    std::cout.flush();
    std::this_thread::sleep_for(std::chrono::seconds(2));

    int pipe_fds[2] = {-1, -1};
    if (::pipe2(pipe_fds, O_CLOEXEC) == 0) {
        held_fds.push_back(pipe_fds[0]);
        held_fds.push_back(pipe_fds[1]);
    }

    int event_fd = ::eventfd(1, EFD_CLOEXEC);
    if (event_fd >= 0) {
        held_fds.push_back(event_fd);
        int dup_fd = ::dup(event_fd);
        if (dup_fd >= 0) {
            held_fds.push_back(dup_fd);
        }
    }

    int timer_fd = ::timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (timer_fd >= 0) {
        held_fds.push_back(timer_fd);
    }

    sigset_t mask;
    ::sigemptyset(&mask);
    ::sigaddset(&mask, SIGUSR1);
    int signal_fd = ::signalfd(-1, &mask, SFD_CLOEXEC);
    if (signal_fd >= 0) {
        held_fds.push_back(signal_fd);
    }

    int mem_fd = ::memfd_create("fd-sources-demo", MFD_CLOEXEC);
    if (mem_fd >= 0) {
        held_fds.push_back(mem_fd);
    }

    int socket_fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socket_fd >= 0) {
        held_fds.push_back(socket_fd);
    }

    io_uring_params params{};
    int ring_fd = static_cast<int>(::syscall(SYS_io_uring_setup, 2, &params));
    if (ring_fd >= 0) {
        held_fds.push_back(ring_fd);
    }

    int range_first = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    int range_second = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (range_first >= 0 && range_second >= 0) {
        int begin = std::min(range_first, range_second);
        int end = std::max(range_first, range_second);
        if (::syscall(SYS_close_range, static_cast<unsigned int>(begin),
                      static_cast<unsigned int>(end), 0) == 0) {
            range_first = -1;
            range_second = -1;
        }
    }
    if (range_first >= 0) {
        held_fds.push_back(range_first);
    }
    if (range_second >= 0) {
        held_fds.push_back(range_second);
    }

    std::cout << "fd_sources_demo held=" << held_fds.size() << '\n';
    std::cout.flush();
    std::this_thread::sleep_for(std::chrono::seconds(10));

    for (int fd : held_fds) {
        ::close(fd);
    }
    return 0;
}
