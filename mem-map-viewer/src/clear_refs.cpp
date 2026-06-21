#include "mem_map_viewer.hpp"
#include "unique_fd.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <unistd.h>

namespace mmv {
namespace {

std::string clear_refs_path(int pid) {
    std::ostringstream path;
    path << "/proc/" << pid << "/clear_refs";
    return path.str();
}

}  // namespace

ClearRefsReport clear_soft_dirty(int pid) {
    ClearRefsReport report;
    report.pid = pid;
    report.mode = "soft-dirty";

    UniqueFd fd(::open(clear_refs_path(pid).c_str(), O_WRONLY | O_CLOEXEC));
    if (!fd) {
        report.error = std::string("open clear_refs failed: ") + std::strerror(errno);
        return report;
    }

    constexpr char kClearSoftDirty[] = "4\n";
    ssize_t n = ::write(fd.get(), kClearSoftDirty, sizeof(kClearSoftDirty) - 1);
    if (n != static_cast<ssize_t>(sizeof(kClearSoftDirty) - 1)) {
        report.error = std::string("write clear_refs failed: ") +
                       (n < 0 ? std::strerror(errno) : "short write");
        return report;
    }

    report.available = true;
    return report;
}

}  // namespace mmv
