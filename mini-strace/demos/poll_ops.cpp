#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

namespace {

void close_no_errno(int fd) {
    const int saved = errno;
    if (fd >= 0) {
        (void)::close(fd);
    }
    errno = saved;
}

bool write_one(int fd) {
    const char byte = 'p';
    return ::write(fd, &byte, 1) == 1;
}

}  // namespace

int main() {
    int pipe_fds[2] = {-1, -1};
    if (::pipe2(pipe_fds, O_CLOEXEC | O_NONBLOCK) != 0) {
        return 1;
    }
    if (!write_one(pipe_fds[1])) {
        close_no_errno(pipe_fds[0]);
        close_no_errno(pipe_fds[1]);
        return 1;
    }

    pollfd fds[2] = {
        {pipe_fds[0], static_cast<short>(POLLIN | POLLERR), 0},
        {pipe_fds[1], POLLOUT, 0},
    };
    const int poll_rc = ::poll(fds, 2, 0);

    timespec timeout{};
    const int ppoll_rc = ::ppoll(fds, 2, &timeout, nullptr);

    close_no_errno(pipe_fds[0]);
    close_no_errno(pipe_fds[1]);
    return poll_rc >= 2 && ppoll_rc >= 2 ? 0 : 1;
}
