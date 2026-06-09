#pragma once

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

namespace fdi {

enum class FdType {
    File,
    Dir,
    CharDev,
    BlockDev,
    Fifo,
    Pipe,
    Socket,
    EventPoll,
    EventFd,
    TimerFd,
    SignalFd,
    Inotify,
    Fanotify,
    AnonOther,
    Unknown,
};

struct SocketInfo {
    std::string proto;
    std::string local_addr;
    std::string remote_addr;
    std::string state;
    std::string path;
    std::string source;
    bool source_conflict = false;
    bool has_tcp_info = false;
    uint32_t rtt_us = 0;
    uint32_t snd_cwnd = 0;
    uint32_t retrans = 0;
    std::optional<uint32_t> rqueue;
    std::optional<uint32_t> wqueue;
    std::optional<uint32_t> rmem;
    std::optional<uint32_t> wmem;
    std::optional<uint32_t> drops;
    std::optional<uint32_t> peer_inode;
    std::optional<uint32_t> unix_rqueue;
    std::optional<uint32_t> unix_wqueue;
    std::string congestion;
};

struct EpollTarget {
    int fd = -1;
    std::string events;
    std::string data;
};

struct InotifyWatch {
    int wd = -1;
    uint64_t inode = 0;
    std::string device;
    std::string mask;
    std::string ignored_mask;
    std::string file_handle;
};

struct FanotifyMark {
    std::optional<int> mnt_id;
    uint64_t inode = 0;
    std::string device;
    std::string mark_flags;
    std::string mask;
    std::string ignored_mask;
    std::string file_handle;
};

struct GrowthBucket {
    std::string key;
    int growth = 0;
};

struct FdEntry {
    int fd = -1;
    FdType type = FdType::Unknown;
    std::string target;
    uint64_t inode = 0;
    int flags = 0;
    int fd_flags = 0;
    bool flags_valid = false;
    bool fd_flags_valid = false;
    bool deleted = false;
    uint64_t size = 0;
    uint64_t device = 0;
    long fs_type = 0;
    std::string mount_point;
    std::string mount_root;
    std::optional<SocketInfo> socket;
    std::optional<uint64_t> pos;
    std::optional<int> fdinfo_flags;
    std::optional<int> mnt_id;
    std::optional<uint64_t> fdinfo_inode;
    std::vector<EpollTarget> epoll_targets;
    std::optional<uint64_t> eventfd_count;
    std::optional<uint64_t> eventfd_id;
    std::optional<int> timerfd_clockid;
    std::optional<uint64_t> timerfd_ticks;
    std::optional<std::string> signal_mask;
    std::vector<InotifyWatch> inotify_watches;
    std::vector<FanotifyMark> fanotify_marks;
};

struct InspectOptions {
    int max_fd = 65536;
    bool force_proc_fallback = false;
    bool use_io_uring = false;
};

struct LeakReport {
    std::vector<FdEntry> first;
    std::vector<FdEntry> last;
    int file_growth = 0;
    int socket_growth = 0;
    int pipe_growth = 0;
    int total_growth = 0;
    int close_wait_count = 0;
    int sample_count = 0;
    bool monotonic_growth = false;
    bool suspected = false;
    std::string verdict;
    std::vector<std::string> new_targets;
    std::vector<GrowthBucket> growth_buckets;
};

std::vector<FdEntry> inspect_pid(int pid, const InspectOptions& options);
LeakReport check_leak(int pid, int seconds, const InspectOptions& options);

const char* type_name(FdType type);
void print_table(std::ostream& out, const std::vector<FdEntry>& entries, bool only_socket);
void print_json(std::ostream& out, const std::vector<FdEntry>& entries, bool only_socket);
void print_leak_report(std::ostream& out, const LeakReport& report, bool json);

}  // namespace fdi
