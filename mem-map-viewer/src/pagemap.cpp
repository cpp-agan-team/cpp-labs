#include "mem_map_viewer.hpp"
#include "unique_fd.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>

namespace mmv {
namespace {

constexpr uint64_t kPresent = 1ULL << 63U;
constexpr uint64_t kSwapped = 1ULL << 62U;
constexpr uint64_t kFileOrShared = 1ULL << 61U;
constexpr uint64_t kExclusive = 1ULL << 56U;
constexpr uint64_t kSoftDirty = 1ULL << 55U;
constexpr uint64_t kPfnMask = (1ULL << 55U) - 1;
constexpr uint64_t kMaxPagesPerScan = 1024ULL * 1024ULL;
constexpr uint64_t kPagemapEntrySize = sizeof(uint64_t);

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

void count_entry(uint64_t entry, PageMapReport* report) {
    if ((entry & kPresent) != 0) {
        ++report->present_pages;
    }
    if ((entry & kSwapped) != 0) {
        ++report->swapped_pages;
    }
    if ((entry & kSoftDirty) != 0) {
        ++report->soft_dirty_pages;
    }
    if ((entry & kFileOrShared) != 0) {
        ++report->file_or_shared_pages;
    }
    if ((entry & kExclusive) != 0) {
        ++report->exclusive_pages;
    }
    if ((entry & kPfnMask) != 0) {
        ++report->pfn_visible_pages;
    }
}

std::string pagemap_path(int pid) {
    std::ostringstream path;
    path << "/proc/" << pid << "/pagemap";
    return path.str();
}

}  // namespace

PageMapReport sample_pagemap(int pid, uint64_t begin, uint64_t length) {
    PageMapReport report;
    report.pid = pid;
    report.page_size = page_size_or_zero();
    if (report.page_size == 0) {
        report.error = "sysconf(_SC_PAGESIZE) failed";
        return report;
    }
    if (length == 0 || std::numeric_limits<uint64_t>::max() - begin < length) {
        report.error = "invalid pagemap range";
        return report;
    }

    report.range_begin = round_down(begin, report.page_size);
    report.range_end = round_up(begin + length, report.page_size);
    report.total_pages = (report.range_end - report.range_begin) / report.page_size;
    if (report.total_pages == 0) {
        report.error = "empty pagemap range";
        return report;
    }
    if (report.total_pages > kMaxPagesPerScan) {
        report.error = "pagemap range is too large; narrow --range";
        return report;
    }

    UniqueFd fd(::open(pagemap_path(pid).c_str(), O_RDONLY | O_CLOEXEC));
    if (!fd) {
        report.error = std::string("open pagemap failed: ") + std::strerror(errno);
        return report;
    }

    for (uint64_t page = 0; page < report.total_pages; ++page) {
        uint64_t entry = 0;
        const uint64_t virtual_page = (report.range_begin / report.page_size) + page;
        if (virtual_page > std::numeric_limits<uint64_t>::max() / kPagemapEntrySize) {
            report.error = "pagemap offset overflow";
            return report;
        }
        const uint64_t offset = virtual_page * kPagemapEntrySize;
        if (offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) {
            report.error = "pagemap offset exceeds off_t";
            return report;
        }
        ssize_t n = ::pread(fd.get(), &entry, sizeof(entry), static_cast<off_t>(offset));
        if (n != static_cast<ssize_t>(sizeof(entry))) {
            report.error = std::string("read pagemap failed: ") +
                           (n < 0 ? std::strerror(errno) : "short read");
            return report;
        }
        count_entry(entry, &report);
    }

    report.available = true;
    report.pfn_visible = report.pfn_visible_pages > 0;
    return report;
}

}  // namespace mmv
