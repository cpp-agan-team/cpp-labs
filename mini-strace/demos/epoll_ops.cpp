#include <cerrno>
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>

namespace {

void close_no_errno(int fd) {
    const int saved = errno;
    if (fd >= 0) {
        (void)::close(fd);
    }
    errno = saved;
}

}  // namespace

int main() {
    int pipe_fds[2] = {-1, -1};
    if (::pipe2(pipe_fds, O_CLOEXEC | O_NONBLOCK) != 0) {
        return 1;
    }

    const int epfd = ::epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        close_no_errno(pipe_fds[0]);
        close_no_errno(pipe_fds[1]);
        return 1;
    }

    epoll_event event{};
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = pipe_fds[0];
    if (::epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_fds[0], &event) != 0) {
        close_no_errno(epfd);
        close_no_errno(pipe_fds[0]);
        close_no_errno(pipe_fds[1]);
        return 1;
    }

    const char byte = 'e';
    if (::write(pipe_fds[1], &byte, 1) != 1) {
        close_no_errno(epfd);
        close_no_errno(pipe_fds[0]);
        close_no_errno(pipe_fds[1]);
        return 1;
    }

    epoll_event ready{};
    const int rc = ::epoll_wait(epfd, &ready, 1, 0);

    close_no_errno(epfd);
    close_no_errno(pipe_fds[0]);
    close_no_errno(pipe_fds[1]);
    return rc == 1 ? 0 : 1;
}
