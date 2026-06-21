#include "internal.hpp"
#include "unique_fd.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/limits.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifndef SYS_pidfd_open
#ifdef __NR_pidfd_open
#define SYS_pidfd_open __NR_pidfd_open
#endif
#endif

#ifndef SYS_pidfd_getfd
#ifdef __NR_pidfd_getfd
#define SYS_pidfd_getfd __NR_pidfd_getfd
#endif
#endif

namespace mmv {

MappingSource resolve_mapping_fd(int pid, int fd, uint64_t offset) {
    MappingSource source;
    source.fd = fd;
    source.offset = offset;
    if (fd < 0) {
        return source;
    }

    std::ostringstream link_path;
    link_path << "/proc/" << pid << "/fd/" << fd;
    std::string buffer(PATH_MAX, '\0');
    ssize_t n = ::readlink(link_path.str().c_str(), &buffer[0], buffer.size() - 1);
    if (n >= 0) {
        buffer.resize(static_cast<size_t>(n));
        constexpr const char* kDeletedSuffix = " (deleted)";
        if (detail::ends_with(buffer, kDeletedSuffix)) {
            source.deleted = true;
            buffer.resize(buffer.size() - std::strlen(kDeletedSuffix));
        }
        source.path = buffer;
    }

#if defined(SYS_pidfd_open) && defined(SYS_pidfd_getfd)
    UniqueFd pidfd(static_cast<int>(::syscall(SYS_pidfd_open, pid, 0)));
    if (pidfd) {
        UniqueFd copied(static_cast<int>(::syscall(SYS_pidfd_getfd, pidfd.get(), fd, 0)));
        if (copied) {
            struct stat st {};
            if (::fstat(copied.get(), &st) == 0) {
                source.inode = static_cast<uint64_t>(st.st_ino);
                source.device = static_cast<uint64_t>(st.st_dev);
            }
        }
    }
#endif

    return source;
}

}  // namespace mmv
