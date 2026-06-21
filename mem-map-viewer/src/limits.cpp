#include "mem_map_viewer.hpp"

#include <cerrno>
#include <cstring>
#include <limits>
#include <sys/resource.h>

namespace mmv {
namespace {

struct LimitDef {
    int resource = 0;
    const char* name = "";
};

constexpr LimitDef kLimits[] = {
    {RLIMIT_AS, "address_space"}, {RLIMIT_DATA, "data"}, {RLIMIT_STACK, "stack"},
    {RLIMIT_MEMLOCK, "memlock"},  {RLIMIT_RSS, "rss"},
};

uint64_t rlim_to_u64(rlim_t value) {
    if (value == RLIM_INFINITY) {
        return std::numeric_limits<uint64_t>::max();
    }
    return static_cast<uint64_t>(value);
}

}  // namespace

ResourceLimitsReport read_resource_limits(int pid) {
    ResourceLimitsReport report;
    report.pid = pid;
    for (const LimitDef& def : kLimits) {
        rlimit limit{};
        if (::prlimit(pid, static_cast<__rlimit_resource>(def.resource), nullptr, &limit) != 0) {
            report.error =
                std::string("prlimit failed for ") + def.name + ": " + std::strerror(errno);
            return report;
        }
        ResourceLimitEntry entry;
        entry.name = def.name;
        entry.soft_infinity = limit.rlim_cur == RLIM_INFINITY;
        entry.hard_infinity = limit.rlim_max == RLIM_INFINITY;
        entry.soft = rlim_to_u64(limit.rlim_cur);
        entry.hard = rlim_to_u64(limit.rlim_max);
        report.limits.push_back(entry);
    }
    report.available = true;
    return report;
}

}  // namespace mmv
