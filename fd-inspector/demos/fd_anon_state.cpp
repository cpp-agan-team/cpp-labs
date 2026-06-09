#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <signal.h>
#include <string>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

void close_all(const std::vector<int>& fds) {
    for (int fd : fds) {
        if (fd >= 0) {
            ::close(fd);
        }
    }
}

}  // namespace

int main() {
    std::vector<int> held_fds;

    int event_fd = ::eventfd(7, EFD_CLOEXEC);
    if (event_fd >= 0) {
        held_fds.push_back(event_fd);
    }

    int epoll_fd = ::epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd >= 0) {
        held_fds.push_back(epoll_fd);
        if (event_fd >= 0) {
            epoll_event interest{};
            interest.events = EPOLLIN;
            interest.data.fd = event_fd;
            ::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event_fd, &interest);
        }
    }

    int timer_fd = ::timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (timer_fd >= 0) {
        held_fds.push_back(timer_fd);
        itimerspec spec{};
        spec.it_value.tv_sec = 60;
        ::timerfd_settime(timer_fd, 0, &spec, nullptr);
    }

    sigset_t mask;
    ::sigemptyset(&mask);
    ::sigaddset(&mask, SIGUSR1);
    ::sigprocmask(SIG_BLOCK, &mask, nullptr);
    int signal_fd = ::signalfd(-1, &mask, SFD_CLOEXEC);
    if (signal_fd >= 0) {
        held_fds.push_back(signal_fd);
    }

    char dir_template[] = "/tmp/fd-anon-state-XXXXXX";
    char* watched_dir = ::mkdtemp(dir_template);
    int inotify_fd = ::inotify_init1(IN_CLOEXEC);
    int watch = -1;
    if (inotify_fd >= 0) {
        held_fds.push_back(inotify_fd);
        if (watched_dir) {
            watch = ::inotify_add_watch(inotify_fd, watched_dir, IN_CREATE | IN_DELETE);
        }
    }

    std::cout << "fd_anon_state_demo pid=" << getpid() << '\n';
    if (watched_dir) {
        std::cout << "watched_dir=" << watched_dir << '\n';
    }
    std::cout << "Run: fd-inspector --pid " << getpid() << " --json | jq\n";
    std::cout.flush();

    std::this_thread::sleep_for(std::chrono::seconds(30));

    if (inotify_fd >= 0 && watch >= 0) {
        ::inotify_rm_watch(inotify_fd, watch);
    }
    close_all(held_fds);
    if (watched_dir) {
        ::rmdir(watched_dir);
    }
    return 0;
}
