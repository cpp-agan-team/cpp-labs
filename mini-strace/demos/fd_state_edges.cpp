#include <cerrno>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

void close_no_errno(int fd) {
    const int saved = errno;
    if (fd >= 0) {
        (void)::close(fd);
    }
    errno = saved;
}

bool write_one(int fd, char value) {
    return ::write(fd, &value, 1) == 1;
}

bool read_one(int fd) {
    char value = 0;
    return ::read(fd, &value, 1) == 1;
}

}  // namespace

int main() {
    int pipe_fds[2] = {-1, -1};
    if (::pipe2(pipe_fds, O_CLOEXEC) != 0) {
        return 1;
    }

    const int dup_read = ::fcntl(pipe_fds[0], F_DUPFD_CLOEXEC, 10);
    if (dup_read < 0) {
        close_no_errno(pipe_fds[0]);
        close_no_errno(pipe_fds[1]);
        return 1;
    }

    if (!write_one(pipe_fds[1], 'p') || !read_one(dup_read)) {
        close_no_errno(dup_read);
        close_no_errno(pipe_fds[0]);
        close_no_errno(pipe_fds[1]);
        return 1;
    }

    int sockets[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
        close_no_errno(dup_read);
        close_no_errno(pipe_fds[0]);
        close_no_errno(pipe_fds[1]);
        return 1;
    }

    const bool ok = write_one(sockets[0], 's') && read_one(sockets[1]);

    close_no_errno(sockets[0]);
    close_no_errno(sockets[1]);
    close_no_errno(dup_read);
    close_no_errno(pipe_fds[0]);
    close_no_errno(pipe_fds[1]);
    return ok ? 0 : 1;
}
