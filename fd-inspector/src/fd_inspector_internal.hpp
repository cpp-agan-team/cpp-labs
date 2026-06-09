#pragma once

#include "fd_inspector.hpp"

#include <cstdint>
#include <linux/stat.h>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace fdi::detail {

struct ProcFdSnapshot {
    int fd = -1;
    std::string target;
    bool has_target = false;
    struct statx stx {};
    bool has_statx = false;
};

struct MountInfo {
    std::string root;
    std::string mount_point;
    std::string fs_type;
};

std::runtime_error errno_error(const std::string& action);
std::string trim(std::string value);
bool starts_with(const std::string& value, const std::string& prefix);
bool ends_with(const std::string& value, const std::string& suffix);
std::optional<uint64_t> parse_unsigned(const std::string& value, int base = 10);
std::optional<int> parse_int(const std::string& value, int base = 10);
bool parse_fd_name(const char* name, int* fd);
std::vector<std::string> split_fields(const std::string& line);
std::string decode_mount_field(const std::string& value);
std::string read_self_fd_target(int fd);
std::string read_target_fd_link(int pid, int fd);
std::string value_after_colon(const std::string& line);
std::string token_after(const std::string& line, const std::string& token);
std::optional<uint64_t> bracket_inode(const std::string& target, const std::string& prefix);

FdType type_from_target(const std::string& target);
void fill_entry_from_stat(const struct stat& st, FdEntry* entry);
void fill_entry_from_statx(const struct statx& stx, FdEntry* entry);

void fill_socket_info(int fd, FdEntry* entry);
std::map<uint64_t, SocketInfo> load_socket_diag_for_pid(int pid);
void attach_diag_info(const std::map<uint64_t, SocketInfo>& by_inode, FdEntry* entry);

int syscall_pidfd_open(int pid);
int syscall_pidfd_getfd(int pidfd, int target_fd);
int scan_limit_for_pid(int pid, const InspectOptions& options);
std::vector<int> list_target_fds(int pid, int max_fd, bool* used_range_fallback,
                                 int* skipped_for_limit);

std::optional<std::map<int, ProcFdSnapshot>> read_proc_fd_snapshots_io_uring(
    int pid, const std::vector<int>& fds);
void inspect_copied_fd(int fd, int target_fd, const ProcFdSnapshot* snapshot, FdEntry* entry);
void inspect_proc_fd(int pid, int target_fd, const ProcFdSnapshot* snapshot, FdEntry* entry);
std::map<int, MountInfo> read_mountinfo(int pid);
void attach_mount_info(const std::map<int, MountInfo>& mounts, FdEntry* entry);
void read_fdinfo(int pid, FdEntry* entry);

bool is_permission_error(int error);
void warn_permission_fallback(const std::string& operation, int error);

}  // namespace fdi::detail
