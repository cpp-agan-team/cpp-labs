#include "mem_map_viewer.hpp"

#include <cerrno>
#include <cstring>
#include <limits>
#include <map>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

#ifndef SYS_move_pages
#ifdef __NR_move_pages
#define SYS_move_pages __NR_move_pages
#endif
#endif

namespace mmv {
namespace {

constexpr uint64_t kMaxPagesPerScan = 1024ULL * 1024ULL;

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

bool query_page_locations(int pid, std::vector<void*>* pages, std::vector<int>* status,
                          std::string* error) {
#ifdef SYS_move_pages
    long rc = ::syscall(SYS_move_pages, pid, static_cast<unsigned long>(pages->size()),
                        pages->data(), nullptr, status->data(), 0);
    if (rc != 0) {
        *error = std::string("move_pages failed: ") + std::strerror(errno);
        return false;
    }
    return true;
#else
    (void)pid;
    (void)pages;
    (void)status;
    *error = "move_pages syscall is not available";
    return false;
#endif
}

}  // namespace

NumaReport sample_numa(int pid, uint64_t begin, uint64_t length) {
    NumaReport report;
    report.pid = pid;
    report.page_size = page_size_or_zero();
    if (report.page_size == 0) {
        report.error = "sysconf(_SC_PAGESIZE) failed";
        return report;
    }
    if (length == 0 || std::numeric_limits<uint64_t>::max() - begin < length) {
        report.error = "invalid numa range";
        return report;
    }

    report.range_begin = round_down(begin, report.page_size);
    report.range_end = round_up(begin + length, report.page_size);
    report.total_pages = (report.range_end - report.range_begin) / report.page_size;
    if (report.total_pages == 0) {
        report.error = "empty numa range";
        return report;
    }
    if (report.total_pages > kMaxPagesPerScan) {
        report.error = "numa range is too large; narrow --range";
        return report;
    }

    std::vector<void*> pages;
    pages.reserve(static_cast<size_t>(report.total_pages));
    for (uint64_t page = 0; page < report.total_pages; ++page) {
        uint64_t address = report.range_begin + page * report.page_size;
        pages.push_back(reinterpret_cast<void*>(address));
    }
    std::vector<int> status(pages.size(), 0);
    if (!query_page_locations(pid, &pages, &status, &report.error)) {
        return report;
    }

    std::map<int, uint64_t> nodes;
    std::map<int, uint64_t> statuses;
    for (int item : status) {
        if (item >= 0) {
            ++nodes[item];
            ++report.located_pages;
        } else {
            ++statuses[item];
        }
    }
    for (const auto& item : nodes) {
        report.nodes.push_back(NumaNodeCount{item.first, item.second});
    }
    for (const auto& item : statuses) {
        report.statuses.push_back(NumaStatusCount{item.first, item.second});
    }

    report.available = true;
    return report;
}

}  // namespace mmv
