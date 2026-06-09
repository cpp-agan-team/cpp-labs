#include "fd_inspector_internal.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <linux/limits.h>
#include <sstream>
#include <sys/sysmacros.h>
#include <unistd.h>

namespace fdi::detail {

std::runtime_error errno_error(const std::string& action) {
    return std::runtime_error(action + ": " + std::strerror(errno));
}

std::string trim(std::string value) {
    const char* whitespace = " \t\r\n";
    size_t begin = value.find_first_not_of(whitespace);
    if (begin == std::string::npos) {
        return {};
    }
    size_t end = value.find_last_not_of(whitespace);
    return value.substr(begin, end - begin + 1);
}

bool starts_with(const std::string& value, const std::string& prefix) {
    return value.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), value.begin());
}

bool ends_with(const std::string& value, const std::string& suffix) {
    if (suffix.size() > value.size()) {
        return false;
    }
    return std::equal(suffix.rbegin(), suffix.rend(), value.rbegin());
}

std::optional<uint64_t> parse_unsigned(const std::string& value, int base) {
    std::string text = trim(value);
    if (text.empty()) {
        return std::nullopt;
    }

    errno = 0;
    char* end = nullptr;
    unsigned long long parsed = std::strtoull(text.c_str(), &end, base);
    if (errno != 0 || end == text.c_str()) {
        return std::nullopt;
    }
    return static_cast<uint64_t>(parsed);
}

std::optional<int> parse_int(const std::string& value, int base) {
    std::optional<uint64_t> parsed = parse_unsigned(value, base);
    if (!parsed || *parsed > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
        return std::nullopt;
    }
    return static_cast<int>(*parsed);
}

bool parse_fd_name(const char* name, int* fd) {
    if (!name || !*name) {
        return false;
    }

    int value = 0;
    for (const char* p = name; *p; ++p) {
        if (*p < '0' || *p > '9') {
            return false;
        }
        if (value > (std::numeric_limits<int>::max() - (*p - '0')) / 10) {
            return false;  // 超出 int 范围的 fd 号不可能合法，拒绝以防溢出
        }
        value = value * 10 + (*p - '0');
    }
    *fd = value;
    return true;
}

std::vector<std::string> split_fields(const std::string& line) {
    std::istringstream input(line);
    std::vector<std::string> fields;
    std::string field;
    while (input >> field) {
        fields.push_back(field);
    }
    return fields;
}

std::string decode_mount_field(const std::string& value) {
    std::string decoded;
    decoded.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\\' && i + 3 < value.size() && value[i + 1] >= '0' &&
            value[i + 1] <= '7' && value[i + 2] >= '0' && value[i + 2] <= '7' &&
            value[i + 3] >= '0' && value[i + 3] <= '7') {
            int ch = (value[i + 1] - '0') * 64 + (value[i + 2] - '0') * 8 + (value[i + 3] - '0');
            decoded.push_back(static_cast<char>(ch));
            i += 3;
        } else {
            decoded.push_back(value[i]);
        }
    }
    return decoded;
}

std::string read_self_fd_target(int fd) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    std::string buf(PATH_MAX, '\0');
    ssize_t n = ::readlink(path, &buf[0], buf.size() - 1);
    if (n < 0) {
        return {};
    }
    buf.resize(static_cast<size_t>(n));
    return buf;
}

std::string read_target_fd_link(int pid, int fd) {
    std::ostringstream path;
    path << "/proc/" << pid << "/fd/" << fd;

    std::string buf(PATH_MAX, '\0');
    ssize_t n = ::readlink(path.str().c_str(), &buf[0], buf.size() - 1);
    if (n < 0) {
        return {};
    }
    buf.resize(static_cast<size_t>(n));
    return buf;
}

std::string value_after_colon(const std::string& line) {
    size_t colon = line.find(':');
    if (colon == std::string::npos) {
        return {};
    }
    return trim(line.substr(colon + 1));
}

std::string token_after(const std::string& line, const std::string& token) {
    size_t pos = line.find(token);
    if (pos == std::string::npos) {
        return {};
    }
    pos += token.size();
    while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t' || line[pos] == ':')) {
        ++pos;
    }
    size_t end = pos;
    while (end < line.size() && line[end] != ' ' && line[end] != '\t') {
        ++end;
    }
    return line.substr(pos, end - pos);
}

std::optional<uint64_t> bracket_inode(const std::string& target, const std::string& prefix) {
    if (!starts_with(target, prefix)) {
        return std::nullopt;
    }
    size_t begin = target.find('[');
    size_t end = target.find(']', begin == std::string::npos ? 0 : begin + 1);
    if (begin == std::string::npos || end == std::string::npos || begin + 1 >= end) {
        return std::nullopt;
    }
    return parse_unsigned(target.substr(begin + 1, end - begin - 1));
}

FdType type_from_target(const std::string& target) {
    if (target.find("socket:[") == 0) {
        return FdType::Socket;
    }
    if (target.find("anon_inode:[eventpoll]") != std::string::npos) {
        return FdType::EventPoll;
    }
    if (target.find("anon_inode:[eventfd]") != std::string::npos) {
        return FdType::EventFd;
    }
    if (target.find("anon_inode:[timerfd]") != std::string::npos) {
        return FdType::TimerFd;
    }
    if (target.find("anon_inode:[signalfd]") != std::string::npos) {
        return FdType::SignalFd;
    }
    if (target.find("anon_inode:inotify") != std::string::npos ||
        target.find("anon_inode:[inotify]") != std::string::npos) {
        return FdType::Inotify;
    }
    if (target.find("anon_inode:fanotify") != std::string::npos ||
        target.find("anon_inode:[fanotify]") != std::string::npos) {
        return FdType::Fanotify;
    }
    if (target.find("anon_inode:") != std::string::npos) {
        return FdType::AnonOther;
    }
    if (target.find("pipe:[") == 0) {
        return FdType::Pipe;
    }
    return FdType::Unknown;
}

void fill_entry_from_stat(const struct stat& st, FdEntry* entry) {
    entry->inode = static_cast<uint64_t>(st.st_ino);
    entry->device = static_cast<uint64_t>(st.st_dev);
    entry->size = st.st_size > 0 ? static_cast<uint64_t>(st.st_size) : 0;
    if (S_ISREG(st.st_mode)) {
        entry->type = FdType::File;
    } else if (S_ISDIR(st.st_mode)) {
        entry->type = FdType::Dir;
    } else if (S_ISCHR(st.st_mode)) {
        entry->type = FdType::CharDev;
    } else if (S_ISBLK(st.st_mode)) {
        entry->type = FdType::BlockDev;
    } else if (S_ISFIFO(st.st_mode)) {
        entry->type = entry->target.find("pipe:[") == 0 ? FdType::Pipe : FdType::Fifo;
    } else if (S_ISSOCK(st.st_mode)) {
        entry->type = FdType::Socket;
    }
}

void fill_entry_from_statx(const struct statx& stx, FdEntry* entry) {
    entry->inode = static_cast<uint64_t>(stx.stx_ino);
    entry->device = static_cast<uint64_t>(makedev(stx.stx_dev_major, stx.stx_dev_minor));
    entry->size = stx.stx_size > 0 ? static_cast<uint64_t>(stx.stx_size) : 0;
    if (S_ISREG(stx.stx_mode)) {
        entry->type = FdType::File;
    } else if (S_ISDIR(stx.stx_mode)) {
        entry->type = FdType::Dir;
    } else if (S_ISCHR(stx.stx_mode)) {
        entry->type = FdType::CharDev;
    } else if (S_ISBLK(stx.stx_mode)) {
        entry->type = FdType::BlockDev;
    } else if (S_ISFIFO(stx.stx_mode)) {
        entry->type = entry->target.find("pipe:[") == 0 ? FdType::Pipe : FdType::Fifo;
    } else if (S_ISSOCK(stx.stx_mode)) {
        entry->type = FdType::Socket;
    }
}

bool is_permission_error(int error) {
    return error == EPERM || error == EACCES;
}

void warn_permission_fallback(const std::string& operation, int error) {
    std::cerr << "fd-inspector: " << operation << " failed with " << std::strerror(error)
              << "; falling back to /proc metadata. Rich fd-local details may be unavailable. "
                 "Try root/CAP_SYS_PTRACE or check kernel.yama.ptrace_scope.\n";
}

}  // namespace fdi::detail
