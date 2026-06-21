#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <string>
#include <sys/epoll.h>
#include <unistd.h>

namespace {

class DemoFd {
public:
    explicit DemoFd(int fd = -1) noexcept : fd_(fd) {}
    ~DemoFd() { reset(); }

    DemoFd(const DemoFd&) = delete;
    DemoFd& operator=(const DemoFd&) = delete;

    DemoFd(DemoFd&& other) noexcept : fd_(other.release()) {}
    DemoFd& operator=(DemoFd&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    int get() const noexcept { return fd_; }
    explicit operator bool() const noexcept { return fd_ >= 0; }

    int release() noexcept {
        const int old = fd_;
        fd_ = -1;
        return old;
    }

    void reset(int next = -1) noexcept {
        if (fd_ >= 0) {
            (void)::close(fd_);
        }
        fd_ = next;
    }

private:
    int fd_ = -1;
};

bool write_all(int fd, const char* data, std::size_t size) {
    std::size_t written = 0;
    while (written < size) {
        const ssize_t rc = ::write(fd, data + written, size - written);
        if (rc <= 0) {
            return false;
        }
        written += static_cast<std::size_t>(rc);
    }
    return true;
}

}  // namespace

int main() {
    const std::string path =
        "/tmp/mini-strace-io-latency-demo-" + std::to_string(static_cast<long long>(::getpid()));
    DemoFd file(::open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600));
    if (!file) {
        return 1;
    }
    const char payload[] = "mini-strace io latency demo\n";
    if (!write_all(file.get(), payload, sizeof(payload) - 1)) {
        (void)::unlink(path.c_str());
        return 1;
    }
    if (::fsync(file.get()) != 0) {
        (void)::unlink(path.c_str());
        return 1;
    }

    int pipe_fds[2] = {-1, -1};
    if (::pipe2(pipe_fds, O_CLOEXEC | O_NONBLOCK) != 0) {
        (void)::unlink(path.c_str());
        return 1;
    }
    DemoFd read_end(pipe_fds[0]);
    DemoFd write_end(pipe_fds[1]);
    const char byte = 'i';
    if (::write(write_end.get(), &byte, 1) != 1) {
        (void)::unlink(path.c_str());
        return 1;
    }

    pollfd ready_fd{read_end.get(), POLLIN, 0};
    if (::poll(&ready_fd, 1, 0) != 1) {
        (void)::unlink(path.c_str());
        return 1;
    }

    DemoFd epfd(::epoll_create1(EPOLL_CLOEXEC));
    if (!epfd) {
        (void)::unlink(path.c_str());
        return 1;
    }
    epoll_event event{};
    event.events = EPOLLIN;
    event.data.fd = read_end.get();
    if (::epoll_ctl(epfd.get(), EPOLL_CTL_ADD, read_end.get(), &event) != 0) {
        (void)::unlink(path.c_str());
        return 1;
    }
    epoll_event fired{};
    if (::epoll_wait(epfd.get(), &fired, 1, 0) != 1) {
        (void)::unlink(path.c_str());
        return 1;
    }

    (void)::unlink(path.c_str());
    return 0;
}
