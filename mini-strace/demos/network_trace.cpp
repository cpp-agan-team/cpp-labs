#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

int make_server(sockaddr_in& address) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    int one = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
        ::close(fd);
        return -1;
    }
    std::memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(fd);
        return -1;
    }
    socklen_t length = sizeof(address);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        ::close(fd);
        return -1;
    }
    if (::listen(fd, 1) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

int client_main(sockaddr_in address) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return 10;
    }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(fd);
        return 11;
    }
    char ping[] = "ping";
    iovec iov{};
    iov.iov_base = ping;
    iov.iov_len = 4;
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (::sendmsg(fd, &msg, 0) != 4) {
        ::close(fd);
        return 12;
    }
    char buffer[8]{};
    if (::recvfrom(fd, buffer, sizeof(buffer), 0, nullptr, nullptr) != 4) {
        ::close(fd);
        return 13;
    }
    ::close(fd);
    return 0;
}

}  // namespace

int main() {
    sockaddr_in address{};
    const int server = make_server(address);
    if (server < 0) {
        return 1;
    }
    const pid_t child = ::fork();
    if (child < 0) {
        ::close(server);
        return 2;
    }
    if (child == 0) {
        _exit(client_main(address));
    }

    sockaddr_in peer{};
    socklen_t peer_len = sizeof(peer);
    const int accepted =
        ::accept4(server, reinterpret_cast<sockaddr*>(&peer), &peer_len, SOCK_CLOEXEC);
    if (accepted < 0) {
        ::close(server);
        return 3;
    }
    char buffer[8]{};
    iovec iov{};
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (::recvmsg(accepted, &msg, 0) != 4) {
        ::close(accepted);
        ::close(server);
        return 4;
    }
    const char pong[] = "pong";
    if (::sendto(accepted, pong, 4, 0, nullptr, 0) != 4) {
        ::close(accepted);
        ::close(server);
        return 5;
    }
    int status = 0;
    if (::waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        ::close(accepted);
        ::close(server);
        return 6;
    }
    ::close(accepted);
    ::close(server);
    return 0;
}
