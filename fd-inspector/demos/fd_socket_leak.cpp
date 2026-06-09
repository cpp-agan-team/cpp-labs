#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

int make_listener(uint16_t* port) {
    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }

    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    if (::listen(fd, 128) != 0) {
        ::close(fd);
        return -1;
    }

    socklen_t len = sizeof(addr);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        ::close(fd);
        return -1;
    }
    *port = ntohs(addr.sin_port);
    return fd;
}

void make_short_client(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
        const char data[] = "x";
        ::send(fd, data, sizeof(data), MSG_NOSIGNAL);
    }
    ::close(fd);
}

}  // namespace

int main() {
    uint16_t port = 0;
    int listener = make_listener(&port);
    if (listener < 0) {
        std::cerr << "fd_socket_leak_demo: listen failed: " << std::strerror(errno) << '\n';
        return 1;
    }

    std::vector<int> leaked_connections;
    std::cout << "fd_socket_leak_demo pid=" << getpid() << " port=" << port << '\n';
    std::cout << "Run: fd-inspector --pid " << getpid() << " --socket\n";
    std::cout << "Run: fd-inspector --pid " << getpid() << " --leak-check 6\n";
    std::cout.flush();

    while (true) {
        std::thread client(make_short_client, port);

        sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);
        int accepted =
            ::accept4(listener, reinterpret_cast<sockaddr*>(&peer), &peer_len, SOCK_CLOEXEC);
        if (accepted >= 0) {
            leaked_connections.push_back(accepted);
        }

        client.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
}
