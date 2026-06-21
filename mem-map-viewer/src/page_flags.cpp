#include "mem_map_viewer.hpp"
#include "unique_fd.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <map>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>

namespace mmv {
namespace {

struct FlagDef {
    int bit = 0;
    const char* name = "";
};

constexpr std::array<FlagDef, 27> kFlags = {{
    {0, "locked"},         {1, "error"},      {2, "referenced"},   {3, "uptodate"},
    {4, "dirty"},          {5, "lru"},        {6, "active"},       {7, "slab"},
    {8, "writeback"},      {9, "reclaim"},    {10, "buddy"},       {11, "mmap"},
    {12, "anonymous"},     {13, "swapcache"}, {14, "swapbacked"},  {15, "compound_head"},
    {16, "compound_tail"}, {17, "huge"},      {18, "unevictable"}, {19, "hwpoison"},
    {20, "nopage"},        {21, "ksm"},       {22, "thp"},         {23, "balloon"},
    {24, "zero_page"},     {25, "idle"},      {26, "pgtable"},
}};

constexpr uint64_t kPresent = 1ULL << 63U;
constexpr uint64_t kPfnMask = (1ULL << 55U) - 1;
constexpr uint64_t kMaxPagesPerScan = 1024ULL * 1024ULL;
constexpr uint64_t kEntrySize = sizeof(uint64_t);

uint64_t page_size_or_zero() {
    long value = ::sysconf(_SC_PAGESIZE);
    return value > 0 ? static_cast<uint64_t>(value) : 0;
}

uint64_t round_down(uint64_t value, uint64_t unit) {
    return unit == 0 ? value : (value / unit) * unit;
}

uint64_t round_up(uint64_t value, uint64_t unit) {
    if (unit == 0) {
        return value;
    }
    const uint64_t rem = value % unit;
    if (rem == 0) {
        return value;
    }
    if (std::numeric_limits<uint64_t>::max() - value < unit - rem) {
        return std::numeric_limits<uint64_t>::max();
    }
    return value + (unit - rem);
}

std::string pagemap_path(int pid) {
    std::ostringstream path;
    path << "/proc/" << pid << "/pagemap";
    return path.str();
}

bool read_u64_at(int fd, uint64_t index, uint64_t* value, std::string* error) {
    if (index > std::numeric_limits<uint64_t>::max() / kEntrySize) {
        *error = "page flag offset overflow";
        return false;
    }
    uint64_t offset = index * kEntrySize;
    if (offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) {
        *error = "page flag offset exceeds off_t";
        return false;
    }
    ssize_t n = ::pread(fd, value, sizeof(*value), static_cast<off_t>(offset));
    if (n != static_cast<ssize_t>(sizeof(*value))) {
        *error =
            std::string("page flag read failed: ") + (n < 0 ? std::strerror(errno) : "short read");
        return false;
    }
    return true;
}

void aggregate_flags(uint64_t flags, std::map<std::string, uint64_t>* counts) {
    for (const FlagDef& def : kFlags) {
        if ((flags & (1ULL << static_cast<unsigned int>(def.bit))) != 0) {
            ++(*counts)[def.name];
        }
    }
}

}  // namespace

PageFlagsReport sample_page_flags(int pid, uint64_t begin, uint64_t length) {
    PageFlagsReport report;
    report.pid = pid;
    report.page_size = page_size_or_zero();
    if (report.page_size == 0) {
        report.error = "sysconf(_SC_PAGESIZE) failed";
        return report;
    }
    if (length == 0 || std::numeric_limits<uint64_t>::max() - begin < length) {
        report.error = "invalid page flags range";
        return report;
    }

    report.range_begin = round_down(begin, report.page_size);
    report.range_end = round_up(begin + length, report.page_size);
    report.total_pages = (report.range_end - report.range_begin) / report.page_size;
    if (report.total_pages == 0) {
        report.error = "empty page flags range";
        return report;
    }
    if (report.total_pages > kMaxPagesPerScan) {
        report.error = "page flags range is too large; narrow --range";
        return report;
    }

    UniqueFd pagemap(::open(pagemap_path(pid).c_str(), O_RDONLY | O_CLOEXEC));
    if (!pagemap) {
        report.error = std::string("open pagemap failed: ") + std::strerror(errno);
        return report;
    }
    UniqueFd kpageflags(::open("/proc/kpageflags", O_RDONLY | O_CLOEXEC));
    if (!kpageflags) {
        report.error = std::string("open kpageflags failed: ") + std::strerror(errno);
        return report;
    }

    std::map<std::string, uint64_t> counts;
    for (uint64_t page = 0; page < report.total_pages; ++page) {
        const uint64_t virtual_page = (report.range_begin / report.page_size) + page;
        uint64_t entry = 0;
        if (!read_u64_at(pagemap.get(), virtual_page, &entry, &report.error)) {
            return report;
        }
        if ((entry & kPresent) == 0) {
            continue;
        }
        ++report.present_pages;
        const uint64_t pfn = entry & kPfnMask;
        if (pfn == 0) {
            continue;
        }
        uint64_t flags = 0;
        if (!read_u64_at(kpageflags.get(), pfn, &flags, &report.error)) {
            return report;
        }
        ++report.pfn_visible_pages;
        aggregate_flags(flags, &counts);
    }

    for (const auto& item : counts) {
        report.flags.push_back(PageFlagCount{item.first, item.second});
    }
    report.available = true;
    report.pfn_visible = report.pfn_visible_pages > 0;
    return report;
}

}  // namespace mmv
