#include "internal.hpp"

#include <algorithm>
#include <chrono>
#include <map>
#include <thread>

namespace mmv {
namespace {

struct Totals {
    uint64_t size = 0;
    uint64_t rss_kb = 0;
};

struct Trend {
    double slope = 0.0;
    double r2 = 0.0;
};

struct Bucket {
    uint64_t size = 0;
    uint64_t rss_kb = 0;
    uint64_t pss_kb = 0;
    uint64_t count = 0;
};

Totals totals_for(const Snapshot& snapshot) {
    Totals totals;
    for (const Region& region : snapshot.regions) {
        totals.size += detail::region_size(region);
        totals.rss_kb += region.rss_kb;
    }
    return totals;
}

std::map<std::string, Bucket> buckets_for(const Snapshot& snapshot) {
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

std::vector<GrowthBucket> diff_buckets(const Snapshot& first, const Snapshot& last) {
    std::map<std::string, Bucket> before = buckets_for(first);
    std::map<std::string, Bucket> after = buckets_for(last);
    std::map<std::string, bool> keys;
    for (const auto& item : before) {
        keys[item.first] = true;
    }
    for (const auto& item : after) {
        keys[item.first] = true;
    }

    std::vector<GrowthBucket> buckets;
    for (const auto& item : keys) {
        const Bucket& lhs = before[item.first];
        const Bucket& rhs = after[item.first];
        GrowthBucket bucket;
        bucket.key = item.first;
        bucket.size_delta = static_cast<int64_t>(rhs.size) - static_cast<int64_t>(lhs.size);
        bucket.rss_delta = static_cast<int64_t>(rhs.rss_kb) - static_cast<int64_t>(lhs.rss_kb);
        bucket.pss_delta = static_cast<int64_t>(rhs.pss_kb) - static_cast<int64_t>(lhs.pss_kb);
        bucket.count_delta = static_cast<int64_t>(rhs.count) - static_cast<int64_t>(lhs.count);
        if (bucket.size_delta != 0 || bucket.rss_delta != 0 || bucket.pss_delta != 0 ||
            bucket.count_delta != 0) {
            buckets.push_back(std::move(bucket));
        }
    }

    std::sort(buckets.begin(), buckets.end(), [](const GrowthBucket& lhs, const GrowthBucket& rhs) {
        if (lhs.rss_delta != rhs.rss_delta) {
            return lhs.rss_delta > rhs.rss_delta;
        }
        if (lhs.size_delta != rhs.size_delta) {
            return lhs.size_delta > rhs.size_delta;
        }
        return lhs.key < rhs.key;
    });
    return buckets;
}

Trend trend_for(const std::vector<Totals>& totals, bool use_rss) {
    const size_t n = totals.size();
    if (n < 2) {
        return {};
    }

    const double count = static_cast<double>(n);
    double sum_x = 0.0;
    double sum_y = 0.0;
    for (size_t i = 0; i < n; ++i) {
        sum_x += static_cast<double>(i);
        sum_y += static_cast<double>(use_rss ? totals[i].rss_kb : totals[i].size);
    }
    const double mean_x = sum_x / count;
    const double mean_y = sum_y / count;

    double ss_xx = 0.0;
    double ss_xy = 0.0;
    for (size_t i = 0; i < n; ++i) {
        const double x = static_cast<double>(i);
        const double y = static_cast<double>(use_rss ? totals[i].rss_kb : totals[i].size);
        ss_xx += (x - mean_x) * (x - mean_x);
        ss_xy += (x - mean_x) * (y - mean_y);
    }
    if (ss_xx == 0.0) {
        return {};
    }

    Trend trend;
    trend.slope = ss_xy / ss_xx;
    double ss_total = 0.0;
    double ss_residual = 0.0;
    for (size_t i = 0; i < n; ++i) {
        const double x = static_cast<double>(i);
        const double y = static_cast<double>(use_rss ? totals[i].rss_kb : totals[i].size);
        const double fitted = mean_y + trend.slope * (x - mean_x);
        ss_total += (y - mean_y) * (y - mean_y);
        ss_residual += (y - fitted) * (y - fitted);
    }
    if (ss_total == 0.0) {
        trend.r2 = ss_residual == 0.0 ? 1.0 : 0.0;
    } else {
        trend.r2 = std::max(0.0, std::min(1.0, 1.0 - ss_residual / ss_total));
    }
    return trend;
}

}  // namespace

GrowthReport check_growth(int pid, int samples, int interval_ms, const SnapshotOptions& options) {
    GrowthReport report;
    report.pid = pid;
    report.samples = samples;
    report.interval_ms = interval_ms;
    report.monotonic_size = true;
    report.monotonic_rss = true;

    std::vector<Snapshot> snapshots;
    std::vector<Totals> totals_history;
    snapshots.reserve(static_cast<size_t>(samples));
    totals_history.reserve(static_cast<size_t>(samples));
    Totals previous;
    bool have_previous = false;
    for (int i = 0; i < samples; ++i) {
        Snapshot snapshot = read_proc_snapshot(pid, options);
        Totals current = totals_for(snapshot);
        if (have_previous) {
            report.monotonic_size = report.monotonic_size && current.size >= previous.size;
            report.monotonic_rss = report.monotonic_rss && current.rss_kb >= previous.rss_kb;
        }
        previous = current;
        have_previous = true;
        totals_history.push_back(current);
        snapshots.push_back(std::move(snapshot));
        if (i + 1 < samples) {
            std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
        }
    }

    if (!snapshots.empty()) {
        Totals first = totals_for(snapshots.front());
        Totals last = totals_for(snapshots.back());
        report.first_size = first.size;
        report.last_size = last.size;
        report.first_rss_kb = first.rss_kb;
        report.last_rss_kb = last.rss_kb;
        report.buckets = diff_buckets(snapshots.front(), snapshots.back());
        Trend size_trend = trend_for(totals_history, false);
        Trend rss_trend = trend_for(totals_history, true);
        report.size_slope_bytes_per_sample = size_trend.slope;
        report.rss_slope_kb_per_sample = rss_trend.slope;
        report.size_r2 = size_trend.r2;
        report.rss_r2 = rss_trend.r2;
    }
    return report;
}

}  // namespace mmv
