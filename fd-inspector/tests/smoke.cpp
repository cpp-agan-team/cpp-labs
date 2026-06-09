#include "fd_inspector.hpp"
#include "unique_fd.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

const fdi::FdEntry& find_fd(const std::vector<fdi::FdEntry>& entries, int fd) {
    auto it = std::find_if(entries.begin(), entries.end(),
                           [fd](const fdi::FdEntry& entry) { return entry.fd == fd; });
    if (it == entries.end()) {
        throw std::runtime_error("missing fd " + std::to_string(fd));
    }
    return *it;
}

UniqueFd make_tcp_listener() {
    UniqueFd fd(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    require(static_cast<bool>(fd), "socket(AF_INET) failed");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    require(::bind(fd.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0, "bind failed");
    require(::listen(fd.get(), 1) == 0, "listen failed");
    return fd;
}

UniqueFd make_deleted_file() {
    char path[] = "/tmp/fd-inspector-smoke-XXXXXX";
    UniqueFd fd(::mkstemp(path));
    require(static_cast<bool>(fd), "mkstemp failed");

    std::string contents(4096, 'x');
    require(::write(fd.get(), contents.data(), contents.size()) ==
                static_cast<ssize_t>(contents.size()),
            "write deleted file failed");
    require(::unlink(path) == 0, "unlink failed");
    return fd;
}

std::string make_temp_dir() {
    char path[] = "/tmp/fd-inspector-inotify-XXXXXX";
    char* created = ::mkdtemp(path);
    require(created != nullptr, "mkdtemp failed");
    return created;
}

void verify_entries(const std::vector<fdi::FdEntry>& entries, int event_fd, int epoll_fd,
                    int tcp_fd, int unix_fd, int deleted_fd, int inotify_fd) {
    const fdi::FdEntry& event = find_fd(entries, event_fd);
    require(event.flags_valid, "eventfd flags validity missing");
    require(event.eventfd_count && *event.eventfd_count == 7, "eventfd count missing");

    const fdi::FdEntry& epoll = find_fd(entries, epoll_fd);
    require(
        std::any_of(epoll.epoll_targets.begin(), epoll.epoll_targets.end(),
                    [event_fd](const fdi::EpollTarget& target) { return target.fd == event_fd; }),
        "epoll target missing");

    const fdi::FdEntry& tcp = find_fd(entries, tcp_fd);
    require(tcp.socket && tcp.socket->source == "diag", "TCP diag source missing");
    require(tcp.socket->has_tcp_info, "TCP diag info missing");
    require(!tcp.socket->congestion.empty(), "TCP congestion control missing");

    const fdi::FdEntry& unix_socket = find_fd(entries, unix_fd);
    require(unix_socket.socket && unix_socket.socket->source == "diag", "UNIX diag source missing");
    require(unix_socket.socket->peer_inode.has_value(), "UNIX peer inode missing");

    const fdi::FdEntry& deleted = find_fd(entries, deleted_fd);
    require(deleted.deleted, "deleted file marker missing");
    require(deleted.size == 4096, "deleted file size missing");
    require(deleted.fs_type != 0, "deleted file filesystem missing");
    require(!deleted.mount_point.empty(), "deleted file mount point missing");

    const fdi::FdEntry& inotify = find_fd(entries, inotify_fd);
    require(inotify.type == fdi::FdType::Inotify, "inotify type missing");
    require(inotify.inotify_watches.size() == 1, "inotify watch missing");
    require(inotify.inotify_watches.front().wd >= 0, "inotify wd missing");
    require(!inotify.inotify_watches.front().mask.empty(), "inotify mask missing");
}

}  // namespace

int main() {
    try {
        UniqueFd event(::eventfd(7, EFD_CLOEXEC));
        require(static_cast<bool>(event), "eventfd failed");

        UniqueFd epoll(::epoll_create1(EPOLL_CLOEXEC));
        require(static_cast<bool>(epoll), "epoll_create1 failed");
        epoll_event interest{};
        interest.events = EPOLLIN;
        interest.data.fd = event.get();
        require(::epoll_ctl(epoll.get(), EPOLL_CTL_ADD, event.get(), &interest) == 0,
                "epoll_ctl failed");

        UniqueFd tcp = make_tcp_listener();
        int pair[2] = {-1, -1};
        require(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0,
                "socketpair failed");
        UniqueFd left(pair[0]);
        UniqueFd right(pair[1]);
        UniqueFd deleted = make_deleted_file();
        std::string watched_dir = make_temp_dir();
        UniqueFd inotify(::inotify_init1(IN_CLOEXEC));
        require(static_cast<bool>(inotify), "inotify_init1 failed");
        int watch = ::inotify_add_watch(inotify.get(), watched_dir.c_str(), IN_CREATE | IN_DELETE);
        require(watch >= 0, "inotify_add_watch failed");

        fdi::InspectOptions options;
        options.max_fd = 128;
        std::vector<fdi::FdEntry> entries = fdi::inspect_pid(::getpid(), options);
        verify_entries(entries, event.get(), epoll.get(), tcp.get(), left.get(), deleted.get(),
                       inotify.get());

        options.force_proc_fallback = true;
        std::vector<fdi::FdEntry> fallback_entries = fdi::inspect_pid(::getpid(), options);
        verify_entries(fallback_entries, event.get(), epoll.get(), tcp.get(), left.get(),
                       deleted.get(), inotify.get());
        require(::inotify_rm_watch(inotify.get(), watch) == 0, "inotify_rm_watch failed");
        require(::rmdir(watched_dir.c_str()) == 0, "rmdir watched dir failed");
        std::cout << "fd-inspector smoke passed\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "fd-inspector smoke failed: " << ex.what() << '\n';
        return 1;
    }
}
