#include "internal.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

namespace mmv {
namespace {

uint64_t page_size() {
    long value = ::sysconf(_SC_PAGESIZE);
    if (value <= 0) {
        throw std::runtime_error("sysconf(_SC_PAGESIZE) failed");
    }
    return static_cast<uint64_t>(value);
}

uint64_t round_down(uint64_t value, uint64_t align) {
    return value - (value % align);
}

uint64_t round_up(uint64_t value, uint64_t align) {
    if (value % align == 0) {
        return value;
    }
    return value + (align - (value % align));
}

bool is_self_pid(int pid) {
    return pid == static_cast<int>(::getpid());
}

ResidencyEntry approximate_from_smaps(const Region& region, uint64_t page) {
    ResidencyEntry entry;
    entry.begin = region.begin;
    entry.end = region.end;
    entry.key = detail::region_key(region);
    entry.total_pages = detail::region_size(region) / page;
    entry.resident_pages = std::min(entry.total_pages, (region.rss_kb * 1024 + page - 1) / page);
    entry.resident_ratio = entry.total_pages == 0 ? 0.0
                                                  : static_cast<double>(entry.resident_pages) /
                                                        static_cast<double>(entry.total_pages);
    entry.exact = false;
    entry.note = "smaps-rss-approx";
    return entry;
}

ResidencyEntry sample_self_region(const Region& region, uint64_t page) {
    ResidencyEntry entry;
    entry.begin = region.begin;
    entry.end = region.end;
    entry.key = detail::region_key(region);

    if (!region.perms.read || region.begin >= region.end) {
        entry.note = "unreadable";
        return entry;
    }

    const uint64_t aligned_begin = round_down(region.begin, page);
    const uint64_t aligned_end = round_up(region.end, page);
    const uint64_t length = aligned_end - aligned_begin;
    entry.total_pages = length / page;
    if (entry.total_pages == 0) {
        return entry;
    }

    std::vector<unsigned char> vec(static_cast<size_t>(entry.total_pages));
    if (::mincore(reinterpret_cast<void*>(aligned_begin), static_cast<size_t>(length),
                  vec.data()) != 0) {
        entry.note = std::string("mincore-failed: ") + std::strerror(errno);
        return entry;
    }

    for (unsigned char value : vec) {
        if ((value & 1U) != 0) {
            ++entry.resident_pages;
        }
    }
    entry.resident_ratio =
        static_cast<double>(entry.resident_pages) / static_cast<double>(entry.total_pages);
    entry.exact = true;
    entry.note = "mincore";
    return entry;
}

}  // namespace

ResidencyReport sample_residency(const Snapshot& snapshot) {
    ResidencyReport report;
    report.pid = snapshot.pid;
    report.page_size = page_size();
    report.exact = is_self_pid(snapshot.pid);

    report.entries.reserve(snapshot.regions.size());
    for (const Region& region : snapshot.regions) {
        if (report.exact) {
            report.entries.push_back(sample_self_region(region, report.page_size));
        } else {
            report.entries.push_back(approximate_from_smaps(region, report.page_size));
        }
    }

    std::sort(report.entries.begin(), report.entries.end(),
              [](const ResidencyEntry& lhs, const ResidencyEntry& rhs) {
                  if (lhs.resident_pages != rhs.resident_pages) {
                      return lhs.resident_pages > rhs.resident_pages;
                  }
                  return lhs.key < rhs.key;
              });
    return report;
}

}  // namespace mmv
