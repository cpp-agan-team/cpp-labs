#include "internal.hpp"

#include <algorithm>
#include <map>

namespace mmv {
namespace {

struct Bucket {
    uint64_t size = 0;
    uint64_t rss_kb = 0;
    uint64_t pss_kb = 0;
    size_t count = 0;
};

std::map<std::string, Bucket> bucket_snapshot(const Snapshot& snapshot) {
    std::map<std::string, Bucket> buckets;
    for (const Region& region : snapshot.regions) {
        Bucket& bucket = buckets[detail::region_key(region)];
        bucket.size += detail::region_size(region);
        bucket.rss_kb += region.rss_kb;
        bucket.pss_kb += region.pss_kb;
        ++bucket.count;
    }
    return buckets;
}

}  // namespace

std::vector<SummaryEntry> summarize_snapshot(const Snapshot& snapshot) {
    std::vector<SummaryEntry> entries;
    for (const auto& item : bucket_snapshot(snapshot)) {
        SummaryEntry entry;
        entry.key = item.first;
        entry.size = item.second.size;
        entry.rss_kb = item.second.rss_kb;
        entry.pss_kb = item.second.pss_kb;
        entry.count = item.second.count;
        entries.push_back(std::move(entry));
    }
    std::sort(entries.begin(), entries.end(), [](const SummaryEntry& lhs, const SummaryEntry& rhs) {
        if (lhs.size != rhs.size) {
            return lhs.size > rhs.size;
        }
        return lhs.key < rhs.key;
    });
    return entries;
}

std::vector<DiffEntry> diff_snapshots(const Snapshot& before, const Snapshot& after) {
    std::map<std::string, Bucket> left = bucket_snapshot(before);
    std::map<std::string, Bucket> right = bucket_snapshot(after);
    std::map<std::string, bool> keys;
    for (const auto& item : left) {
        keys[item.first] = true;
    }
    for (const auto& item : right) {
        keys[item.first] = true;
    }

    std::vector<DiffEntry> diff;
    for (const auto& item : keys) {
        const Bucket& a = left[item.first];
        const Bucket& b = right[item.first];
        DiffEntry entry;
        entry.key = item.first;
        entry.size_delta = static_cast<int64_t>(b.size) - static_cast<int64_t>(a.size);
        entry.rss_delta = static_cast<int64_t>(b.rss_kb) - static_cast<int64_t>(a.rss_kb);
        entry.pss_delta = static_cast<int64_t>(b.pss_kb) - static_cast<int64_t>(a.pss_kb);
        entry.count_delta = static_cast<int64_t>(b.count) - static_cast<int64_t>(a.count);
        if (entry.size_delta != 0 || entry.rss_delta != 0 || entry.pss_delta != 0 ||
            entry.count_delta != 0) {
            diff.push_back(std::move(entry));
        }
    }

    std::sort(diff.begin(), diff.end(), [](const DiffEntry& lhs, const DiffEntry& rhs) {
        int64_t lhs_abs = lhs.size_delta < 0 ? -lhs.size_delta : lhs.size_delta;
        int64_t rhs_abs = rhs.size_delta < 0 ? -rhs.size_delta : rhs.size_delta;
        if (lhs_abs != rhs_abs) {
            return lhs_abs > rhs_abs;
        }
        return lhs.key < rhs.key;
    });
    return diff;
}

}  // namespace mmv
