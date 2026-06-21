#include "internal.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace mmv {
namespace {

constexpr uint64_t kLargeMappingBytes = 64ULL * 1024 * 1024;

std::string percent(double value) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(1) << (value * 100.0) << "%";
    return out.str();
}

void add_residency_insights(const ResidencyReport& residency, std::vector<Insight>* insights) {
    for (const ResidencyEntry& entry : residency.entries) {
        const uint64_t size = entry.end > entry.begin ? entry.end - entry.begin : 0;
        const uint64_t resident = residency.page_size != 0 &&
                                          entry.resident_pages > UINT64_MAX / residency.page_size
                                      ? UINT64_MAX
                                      : entry.resident_pages * residency.page_size;
        if (size >= kLargeMappingBytes && entry.resident_ratio < 0.10) {
            Insight insight;
            insight.type = "waste";
            insight.key = entry.key;
            insight.score = 1.0 - entry.resident_ratio;
            insight.evidence = detail::format_size(size) + " mapped, " +
                               detail::format_size(resident) + " resident (" +
                               percent(entry.resident_ratio) + ", " + entry.note + ")";
            insight.suggestion =
                "Large mapping is mostly non-resident; consider smaller reservation or madvise.";
            insights->push_back(std::move(insight));
        } else if (size >= kLargeMappingBytes && entry.resident_ratio > 0.80 &&
                   entry.key.find("anonymous") != std::string::npos) {
            Insight insight;
            insight.type = "resident-anon";
            insight.key = entry.key;
            insight.score = entry.resident_ratio;
            insight.evidence = detail::format_size(size) + " anonymous mapping is " +
                               percent(entry.resident_ratio) + " resident";
            insight.suggestion =
                "Large resident anonymous area; verify it is intentional and has a clear owner.";
            insights->push_back(std::move(insight));
        }
    }
}

void add_perf_insights(const PerfSampleReport& perf, std::vector<Insight>* insights) {
    if (!perf.available || perf.total_samples == 0 || perf.hotspots.empty()) {
        return;
    }
    const PerfHotspot& top = perf.hotspots.front();
    const double share = static_cast<double>(top.samples) / static_cast<double>(perf.total_samples);
    if (share < 0.20) {
        return;
    }

    Insight insight;
    insight.type = "hotspot";
    insight.key = top.key;
    insight.score = share;
    const uint64_t avg_weight = top.samples == 0 ? 0 : top.total_weight / top.samples;
    insight.evidence = std::to_string(top.samples) + "/" + std::to_string(perf.total_samples) +
                       " " + perf.event + " samples (" + percent(share) +
                       "), avg_weight=" + std::to_string(avg_weight);
    insight.suggestion =
        "Memory access cost is concentrated here; inspect stride, locality, huge page and NUMA "
        "behavior.";
    insights->push_back(std::move(insight));
}

void add_cgroup_insights(const CgroupMemoryHealth& cgroup, std::vector<Insight>* insights) {
    if (!cgroup.has_limit && cgroup.full.avg10 < 1.0 && cgroup.some.avg10 < 10.0 &&
        cgroup.oom_kill_events == 0) {
        return;
    }

    if (cgroup.oom_risk >= 0.70 || cgroup.usage_ratio >= 0.85 || cgroup.full.avg10 >= 1.0 ||
        cgroup.some.avg10 >= 10.0 || cgroup.oom_kill_events > 0) {
        Insight insight;
        insight.type = "pressure";
        insight.key = cgroup.path;
        insight.score = std::max(cgroup.oom_risk, std::min(1.0, cgroup.full.avg10 / 100.0));
        std::ostringstream evidence;
        evidence << "usage=" << percent(cgroup.usage_ratio) << " some.avg10=" << cgroup.some.avg10
                 << " full.avg10=" << cgroup.full.avg10 << " oom_kill=" << cgroup.oom_kill_events;
        insight.evidence = evidence.str();
        insight.suggestion =
            "Cgroup memory pressure is elevated; inspect resident growth and container limit "
            "headroom.";
        insights->push_back(std::move(insight));
    }
}

const ResourceLimitEntry* find_limit(const ResourceLimitsReport& limits, const std::string& name) {
    auto it = std::find_if(limits.limits.begin(), limits.limits.end(),
                           [&](const ResourceLimitEntry& entry) { return entry.name == name; });
    return it == limits.limits.end() ? nullptr : &*it;
}

uint64_t snapshot_size(const Snapshot& snapshot) {
    uint64_t total = 0;
    for (const Region& region : snapshot.regions) {
        const uint64_t size = detail::region_size(region);
        if (UINT64_MAX - total < size) {
            return UINT64_MAX;
        }
        total += size;
    }
    return total;
}

uint64_t stack_size(const Snapshot& snapshot) {
    uint64_t total = 0;
    for (const Region& region : snapshot.regions) {
        if (region.kind != RegionKind::Stack && region.kind != RegionKind::ThreadStack) {
            continue;
        }
        const uint64_t size = detail::region_size(region);
        if (UINT64_MAX - total < size) {
            return UINT64_MAX;
        }
        total += size;
    }
    return total;
}

void add_limit_insights(const Snapshot& snapshot, const ResourceLimitsReport& limits,
                        std::vector<Insight>* insights) {
    if (!limits.available) {
        return;
    }

    const ResourceLimitEntry* address_space = find_limit(limits, "address_space");
    if (address_space && !address_space->soft_infinity && address_space->soft > 0) {
        const uint64_t total = snapshot_size(snapshot);
        const double ratio = static_cast<double>(total) / static_cast<double>(address_space->soft);
        if (ratio >= 0.80) {
            Insight insight;
            insight.type = "address-limit";
            insight.key = "RLIMIT_AS";
            insight.score = std::min(1.0, ratio);
            insight.evidence = detail::format_size(total) + " mapped / " +
                               detail::format_size(address_space->soft) + " limit (" +
                               percent(ratio) + ")";
            insight.suggestion =
                "Virtual address usage is close to RLIMIT_AS; investigate mapping growth or raise "
                "the process limit.";
            insights->push_back(std::move(insight));
        }
    }

    const ResourceLimitEntry* stack = find_limit(limits, "stack");
    if (stack && !stack->soft_infinity && stack->soft > 0) {
        const uint64_t total = stack_size(snapshot);
        const double ratio = static_cast<double>(total) / static_cast<double>(stack->soft);
        if (ratio >= 0.80) {
            Insight insight;
            insight.type = "stack-limit";
            insight.key = "RLIMIT_STACK";
            insight.score = std::min(1.0, ratio);
            insight.evidence = detail::format_size(total) + " stack mappings / " +
                               detail::format_size(stack->soft) + " limit (" + percent(ratio) + ")";
            insight.suggestion =
                "Stack mappings are close to RLIMIT_STACK; inspect recursion depth, thread count "
                "or "
                "stack size settings.";
            insights->push_back(std::move(insight));
        }
    }
}

}  // namespace

std::vector<Insight> generate_insights(const Snapshot* snapshot, const ResidencyReport* residency,
                                       const PerfSampleReport* perf,
                                       const CgroupMemoryHealth* cgroup,
                                       const ResourceLimitsReport* limits) {
    std::vector<Insight> insights;
    if (residency) {
        add_residency_insights(*residency, &insights);
    }
    if (perf) {
        add_perf_insights(*perf, &insights);
    }
    if (cgroup) {
        add_cgroup_insights(*cgroup, &insights);
    }
    if (snapshot && limits) {
        add_limit_insights(*snapshot, *limits, &insights);
    }

    std::sort(insights.begin(), insights.end(), [](const Insight& lhs, const Insight& rhs) {
        if (lhs.score != rhs.score) {
            return lhs.score > rhs.score;
        }
        return lhs.type < rhs.type;
    });
    return insights;
}

}  // namespace mmv
