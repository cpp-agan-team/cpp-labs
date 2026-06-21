#include "internal.hpp"

#include <algorithm>
#include <map>
#include <sstream>
#include <utility>

namespace mmv {
namespace {

using RegionKey = std::pair<uint64_t, uint64_t>;

std::map<RegionKey, const Region*> index_regions(const std::vector<Region>& regions) {
    std::map<RegionKey, const Region*> index;
    for (const Region& region : regions) {
        if (region.end > region.begin) {
            index[{region.begin, region.end}] = &region;
        }
    }
    return index;
}

std::string describe_region(const Region& region) {
    std::ostringstream out;
    out << kind_name(region.kind) << " " << perms_string(region.perms) << " "
        << detail::source_key(region);
    if (!region.label.empty() && region.label != region.source.path) {
        out << " label=" << region.label;
    }
    return out.str();
}

bool same_metadata(const Region& observed, const Region& truth) {
    return observed.kind == truth.kind &&
           perms_string(observed.perms) == perms_string(truth.perms) &&
           detail::source_key(observed) == detail::source_key(truth);
}

void add_mismatch(ReconcileReport* report, std::string type, uint64_t begin, uint64_t end,
                  std::string observed, std::string truth) {
    ReconcileMismatch mismatch;
    mismatch.type = std::move(type);
    mismatch.begin = begin;
    mismatch.end = end;
    mismatch.observed = std::move(observed);
    mismatch.truth = std::move(truth);
    report->mismatches.push_back(std::move(mismatch));
}

}  // namespace

ReconcileReport reconcile_with_proc_maps(const Snapshot& observed, const SnapshotOptions& options) {
    ReconcileReport report;
    report.pid = observed.pid;
    report.truth_source = "proc-maps";
    report.observed_regions = observed.regions.size();

    Snapshot truth = read_proc_snapshot(observed.pid, options);
    report.truth_regions = truth.regions.size();

    const auto observed_index = index_regions(observed.regions);
    const auto truth_index = index_regions(truth.regions);

    for (const auto& item : truth_index) {
        const auto found = observed_index.find(item.first);
        if (found == observed_index.end()) {
            ++report.missing_regions;
            add_mismatch(&report, "missing", item.first.first, item.first.second, "",
                         describe_region(*item.second));
            continue;
        }
        if (!same_metadata(*found->second, *item.second)) {
            ++report.metadata_mismatches;
            add_mismatch(&report, "metadata", item.first.first, item.first.second,
                         describe_region(*found->second), describe_region(*item.second));
        }
    }

    for (const auto& item : observed_index) {
        if (truth_index.find(item.first) == truth_index.end()) {
            ++report.extra_regions;
            add_mismatch(&report, "extra", item.first.first, item.first.second,
                         describe_region(*item.second), "");
        }
    }

    std::sort(report.mismatches.begin(), report.mismatches.end(),
              [](const ReconcileMismatch& lhs, const ReconcileMismatch& rhs) {
                  if (lhs.begin != rhs.begin) {
                      return lhs.begin < rhs.begin;
                  }
                  if (lhs.end != rhs.end) {
                      return lhs.end < rhs.end;
                  }
                  return lhs.type < rhs.type;
              });

    return report;
}

}  // namespace mmv
