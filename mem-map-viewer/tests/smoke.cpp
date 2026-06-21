#include "internal.hpp"
#include "mem_map_viewer.hpp"
#include "vma_model.hpp"

#include <algorithm>
#include <cassert>
#include <sstream>
#include <unistd.h>
#include <vector>

namespace {

void verify_mremap_preserves_vma_pieces() {
    mmv::Region rw;
    rw.begin = 0x1000;
    rw.end = 0x2000;
    rw.perms = mmv::Perms{true, true, false, false};
    rw.kind = mmv::RegionKind::Anonymous;
    rw.label = "[anon-rw]";

    mmv::Region ro = rw;
    ro.begin = 0x2000;
    ro.end = 0x3000;
    ro.perms = mmv::Perms{true, false, false, false};
    ro.label = "[anon-ro]";

    mmv::Snapshot seed;
    seed.pid = 1;
    seed.regions = {rw, ro};
    mmv::VmaModel model(seed);

    mmv::MapEvent event;
    event.type = mmv::MapEventType::Mremap;
    event.success = true;
    event.address = 0x1000;
    event.length = 0x2000;
    event.new_address = 0x4000;
    event.new_length = 0x2000;
    model.apply(event);

    mmv::Snapshot snapshot = model.snapshot();
    auto at_4000 = std::find_if(snapshot.regions.begin(), snapshot.regions.end(),
                                [](const mmv::Region& r) { return r.begin == 0x4000; });
    auto at_5000 = std::find_if(snapshot.regions.begin(), snapshot.regions.end(),
                                [](const mmv::Region& r) { return r.begin == 0x5000; });
    assert(at_4000 != snapshot.regions.end());
    assert(at_5000 != snapshot.regions.end());
    assert(at_4000->end == 0x5000);
    assert(at_5000->end == 0x6000);
    assert(at_4000->perms.write);
    assert(!at_5000->perms.write);
}

void verify_region_index_boundaries() {
    mmv::Region first;
    first.begin = 0x1000;
    first.end = 0x2000;
    first.label = "[first]";

    mmv::Region second;
    second.begin = 0x3000;
    second.end = 0x4000;
    second.label = "[second]";

    std::vector<mmv::Region> regions = {second, first};
    mmv::detail::RegionIndex index(regions);

    assert(index.find(0x0fff) == nullptr);
    assert(index.find(0x1000) != nullptr);
    assert(index.find(0x1fff) != nullptr);
    assert(index.find(0x2000) == nullptr);
    assert(index.find(0x2800) == nullptr);
    const mmv::Region* match = index.find(0x3000);
    assert(match != nullptr);
    assert(match->label == "[second]");
}

void verify_json_roundtrip_preserves_source() {
    // Regression: parse_snapshot_json once dropped negative fds (regex was [0-9]+,
    // so fd=-1 became fd=0) and never read the deleted flag. Round-trip a region
    // carrying both and assert they survive.
    mmv::Region region;
    region.begin = 0x1000;
    region.end = 0x2000;
    region.perms = mmv::Perms{true, false, false, false};
    region.kind = mmv::RegionKind::FileMapping;
    region.label = "/lib/example.so";
    region.provenance = "seed";
    region.source.fd = -1;
    region.source.inode = 4242;
    region.source.path = "/lib/example.so";
    region.source.deleted = true;

    mmv::Snapshot snapshot;
    snapshot.pid = 1;
    snapshot.regions = {region};

    std::ostringstream json;
    mmv::print_snapshot_json(json, snapshot);
    std::istringstream input(json.str());
    mmv::Snapshot parsed = mmv::parse_snapshot_json(input);

    assert(parsed.regions.size() == 1);
    assert(parsed.regions[0].source.fd == -1);
    assert(parsed.regions[0].source.deleted);
    assert(parsed.regions[0].source.inode == 4242);
}

}  // namespace

int main() {
    verify_mremap_preserves_vma_pieces();
    verify_region_index_boundaries();
    verify_json_roundtrip_preserves_source();

    mmv::SnapshotOptions options;
    options.with_smaps = false;
    options.probe_memory = false;

    mmv::Snapshot snapshot = mmv::read_proc_snapshot(getpid(), options);
    assert(snapshot.pid == getpid());
    assert(!snapshot.regions.empty());

    bool found_readable = false;
    for (const mmv::Region& region : snapshot.regions) {
        assert(region.begin < region.end);
        found_readable = found_readable || region.perms.read;
        assert(!region.provenance.empty());
    }
    assert(found_readable);

    std::vector<mmv::SummaryEntry> summary = mmv::summarize_snapshot(snapshot);
    assert(!summary.empty());

    std::ostringstream json;
    mmv::print_snapshot_json(json, snapshot);
    std::istringstream input(json.str());
    mmv::Snapshot parsed = mmv::parse_snapshot_json(input);
    assert(parsed.pid == snapshot.pid);
    assert(!parsed.regions.empty());

    std::vector<mmv::DiffEntry> diff = mmv::diff_snapshots(snapshot, parsed);
    assert(diff.empty());

    mmv::ResidencyReport residency = mmv::sample_residency(snapshot);
    assert(residency.pid == getpid());
    assert(residency.page_size > 0);
    assert(!residency.entries.empty());

    return 0;
}
