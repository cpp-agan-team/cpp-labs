#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

int close_no_errno(int fd) {
    const int saved = errno;
    const int rc = ::close(fd);
    errno = saved;
    return rc;
}

}  // namespace

int main() {
    int server = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server < 0) {
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close_no_errno(server);
        return 1;
    }
    if (::listen(server, 1) != 0) {
        close_no_errno(server);
        return 1;
    }

    socklen_t addr_len = sizeof(addr);
    if (::getsockname(server, reinterpret_cast<sockaddr*>(&addr), &addr_len) != 0) {
        close_no_errno(server);
        return 1;
    }

    int client = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client < 0) {
        close_no_errno(server);
        return 1;
    }
    if (::connect(client, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close_no_errno(client);
        close_no_errno(server);
        return 1;
    }

    sockaddr_in peer{};
    socklen_t peer_len = sizeof(peer);
    int accepted = ::accept4(server, reinterpret_cast<sockaddr*>(&peer), &peer_len, SOCK_CLOEXEC);
    if (accepted < 0) {
        close_no_errno(client);
        close_no_errno(server);
        return 1;
    }

    close_no_errno(accepted);
    close_no_errno(client);
    close_no_errno(server);
    return 0;
}
