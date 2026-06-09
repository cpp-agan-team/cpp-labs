#include "fd_inspector.hpp"

#include <algorithm>
#include <chrono>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace fdi {
namespace {

std::map<FdType, int> count_by_type(const std::vector<FdEntry>& entries) {
    std::map<FdType, int> counts;
    for (const FdEntry& entry : entries) {
        ++counts[entry.type];
    }
    return counts;
}

int count_close_wait(const std::vector<FdEntry>& entries) {
    int count = 0;
    for (const FdEntry& entry : entries) {
        if (entry.socket && entry.socket->state == "CLOSE_WAIT") {
            ++count;
        }
    }
    return count;
}

std::string leak_key(const FdEntry& entry) {
    std::ostringstream out;
    out << type_name(entry.type) << ':';
    if (entry.socket && !entry.socket->remote_addr.empty()) {
        out << entry.socket->proto << ':' << entry.socket->remote_addr;
    } else if (!entry.target.empty()) {
        out << entry.target;
    } else {
        out << "inode:" << entry.inode;
    }
    return out.str();
}

std::vector<std::string> new_targets(const std::vector<FdEntry>& first,
                                     const std::vector<FdEntry>& last) {
    std::set<std::string> before;
    for (const FdEntry& entry : first) {
        before.insert(leak_key(entry));
    }

    std::vector<std::string> added;
    std::set<std::string> emitted;
    for (const FdEntry& entry : last) {
        std::string key = leak_key(entry);
        if (before.count(key) == 0 && emitted.insert(key).second) {
            added.push_back(key);
        }
    }
    return added;
}

std::map<std::string, int> bucket_counts(const std::vector<FdEntry>& entries) {
    std::map<std::string, int> counts;
    for (const FdEntry& entry : entries) {
        ++counts[leak_key(entry)];
    }
    return counts;
}

std::vector<GrowthBucket> growth_buckets(const std::vector<FdEntry>& first,
                                         const std::vector<FdEntry>& last) {
    std::map<std::string, int> before = bucket_counts(first);
    std::map<std::string, int> after = bucket_counts(last);
    std::vector<GrowthBucket> buckets;

    for (const auto& item : after) {
        int growth = item.second - before[item.first];
        if (growth > 0) {
            buckets.push_back(GrowthBucket{item.first, growth});
        }
    }

    std::sort(buckets.begin(), buckets.end(), [](const GrowthBucket& a, const GrowthBucket& b) {
        if (a.growth != b.growth) {
            return a.growth > b.growth;
        }
        return a.key < b.key;
    });
    return buckets;
}

bool is_monotonic_non_decreasing(const std::vector<int>& values) {
    for (size_t i = 1; i < values.size(); ++i) {
        if (values[i] < values[i - 1]) {
            return false;
        }
    }
    return true;
}

}  // namespace

LeakReport check_leak(int pid, int seconds, const InspectOptions& options) {
    if (seconds <= 0) {
        throw std::invalid_argument("leak-check seconds must be positive");
    }

    std::vector<std::vector<FdEntry>> samples;
    std::vector<int> totals;
    samples.reserve(static_cast<size_t>(seconds) + 1);
    totals.reserve(static_cast<size_t>(seconds) + 1);

    for (int i = 0; i <= seconds; ++i) {
        samples.push_back(inspect_pid(pid, options));
        totals.push_back(static_cast<int>(samples.back().size()));
        if (i != seconds) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    LeakReport report;
    report.first = samples.front();
    report.last = samples.back();
    report.sample_count = static_cast<int>(samples.size());
    report.monotonic_growth = is_monotonic_non_decreasing(totals);

    auto first_counts = count_by_type(report.first);
    auto last_counts = count_by_type(report.last);
    report.total_growth =
        static_cast<int>(report.last.size()) - static_cast<int>(report.first.size());
    report.file_growth = last_counts[FdType::File] - first_counts[FdType::File];
    report.socket_growth = last_counts[FdType::Socket] - first_counts[FdType::Socket];
    report.pipe_growth = last_counts[FdType::Pipe] - first_counts[FdType::Pipe];
    report.close_wait_count = count_close_wait(report.last);

    report.new_targets = new_targets(report.first, report.last);
    report.growth_buckets = growth_buckets(report.first, report.last);
    report.suspected = report.total_growth > 0 && report.monotonic_growth;
    if (report.socket_growth > 0 && report.close_wait_count > 0) {
        report.verdict = "suspected connection leak: socket count grew and CLOSE_WAIT is present";
    } else if (report.suspected) {
        report.verdict = "suspected fd leak: fd counts grew monotonically during the sample window";
    } else if (report.total_growth > 0) {
        report.verdict = "fd count ended higher, but samples were not monotonic";
    } else {
        report.verdict = "no leak detected";
    }
    return report;
}

}  // namespace fdi
