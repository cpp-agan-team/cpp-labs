#include "vma_model.hpp"

#include "internal.hpp"

#include <algorithm>
#include <sys/mman.h>

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

namespace mmv {
namespace {

uint64_t checked_end(uint64_t begin, uint64_t length) {
    if (UINT64_MAX - begin < length) {
        return UINT64_MAX;
    }
    return begin + length;
}

bool overlaps(const Region& region, uint64_t begin, uint64_t end) {
    return region.begin < end && begin < region.end;
}

Region clip_region(const Region& region, uint64_t begin, uint64_t end) {
    Region clipped = region;
    const uint64_t clipped_begin = std::max(region.begin, begin);
    if (clipped_begin > region.begin &&
        (!region.source.path.empty() || region.source.inode != 0 || region.source.device != 0)) {
        clipped.source.offset += clipped_begin - region.begin;
    }
    clipped.begin = clipped_begin;
    clipped.end = std::min(region.end, end);
    return clipped;
}

}  // namespace

VmaModel::VmaModel(Snapshot seed) : snapshot_(std::move(seed)) {
    for (const Region& region : snapshot_.regions) {
        if (region.kind == RegionKind::Heap) {
            heap_base_ = region.begin;
            break;
        }
    }
    sort_and_merge();
}

void VmaModel::apply(const MapEvent& event) {
    snapshot_.timestamp_ns = event.timestamp_ns;
    if (!event.success && event.type != MapEventType::ProcSeed) {
        return;
    }

    switch (event.type) {
        case MapEventType::Mmap: {
            Region region;
            region.begin = event.address;
            region.end = checked_end(event.address, event.length);
            region.perms = event.perms;
            region.source = event.source;
            region.provenance = "event";
            if (region.source.path.empty() && event.fd < 0) {
                region.label = "[anon]";
            } else {
                region.label = region.source.path;
            }
            region.kind = detail::classify_region(region);
            map_region(std::move(region));
            break;
        }
        case MapEventType::Munmap:
            unmap_range(event.address, checked_end(event.address, event.length));
            break;
        case MapEventType::Mprotect:
            protect_range(event.address, checked_end(event.address, event.length), event.perms);
            break;
        case MapEventType::Brk:
            apply_brk(static_cast<uint64_t>(event.result));
            break;
        case MapEventType::Mremap:
            remap_range(event.address, event.length, event.new_address, event.new_length,
                        event.flags);
            break;
        case MapEventType::Exec:
            snapshot_.regions.clear();
            heap_base_ = 0;
            break;
        case MapEventType::ProcSeed:
            break;
    }
}

Snapshot VmaModel::snapshot() const {
    return snapshot_;
}

void VmaModel::map_region(Region region) {
    if (region.begin >= region.end) {
        return;
    }
    unmap_range(region.begin, region.end);
    snapshot_.regions.push_back(std::move(region));
    sort_and_merge();
}

void VmaModel::unmap_range(uint64_t begin, uint64_t end) {
    if (begin >= end) {
        return;
    }

    std::vector<Region> next;
    for (const Region& region : snapshot_.regions) {
        if (!overlaps(region, begin, end)) {
            next.push_back(region);
            continue;
        }
        if (region.begin < begin) {
            Region left = region;
            left.end = begin;
            next.push_back(left);
        }
        if (end < region.end) {
            Region right = region;
            right.begin = end;
            next.push_back(right);
        }
    }
    snapshot_.regions = std::move(next);
    sort_and_merge();
}

void VmaModel::protect_range(uint64_t begin, uint64_t end, const Perms& perms) {
    if (begin >= end) {
        return;
    }

    std::vector<Region> next;
    for (const Region& region : snapshot_.regions) {
        if (!overlaps(region, begin, end)) {
            next.push_back(region);
            continue;
        }
        if (region.begin < begin) {
            Region left = region;
            left.end = begin;
            next.push_back(left);
        }
        Region middle = region;
        middle.begin = std::max(region.begin, begin);
        middle.end = std::min(region.end, end);
        middle.perms = perms;
        middle.provenance = "event";
        next.push_back(middle);
        if (end < region.end) {
            Region right = region;
            right.begin = end;
            next.push_back(right);
        }
    }
    snapshot_.regions = std::move(next);
    sort_and_merge();
}

void VmaModel::remap_range(uint64_t old_begin, uint64_t old_size, uint64_t new_begin,
                           uint64_t new_size, uint64_t flags) {
    uint64_t old_end = checked_end(old_begin, old_size);
    std::vector<Region> pieces;
    for (const Region& region : snapshot_.regions) {
        if (overlaps(region, old_begin, old_end)) {
            pieces.push_back(clip_region(region, old_begin, old_end));
        }
    }
    if ((flags & MREMAP_DONTUNMAP) == 0) {
        unmap_range(old_begin, old_end);
    }
    for (Region& piece : pieces) {
        const uint64_t relative_begin = piece.begin - old_begin;
        if (relative_begin >= new_size) {
            continue;
        }
        const uint64_t mapped_size = std::min(piece.end - piece.begin, new_size - relative_begin);
        piece.begin = checked_end(new_begin, relative_begin);
        piece.end = checked_end(piece.begin, mapped_size);
        map_region(std::move(piece));
    }
}

void VmaModel::apply_brk(uint64_t new_brk) {
    if (new_brk == 0) {
        return;
    }
    auto it = std::find_if(snapshot_.regions.begin(), snapshot_.regions.end(),
                           [](const Region& region) { return region.kind == RegionKind::Heap; });
    if (it != snapshot_.regions.end()) {
        if (new_brk > it->begin) {
            it->end = new_brk;
        }
        sort_and_merge();
        return;
    }
    if (heap_base_ == 0) {
        heap_base_ = new_brk;
        return;
    }
    if (new_brk > heap_base_) {
        Region heap;
        heap.begin = heap_base_;
        heap.end = new_brk;
        heap.perms = Perms{true, true, false, false};
        heap.kind = RegionKind::Heap;
        heap.label = "[heap]";
        heap.provenance = "inferred";
        map_region(std::move(heap));
    }
}

void VmaModel::sort_and_merge() {
    std::sort(snapshot_.regions.begin(), snapshot_.regions.end(),
              [](const Region& lhs, const Region& rhs) { return lhs.begin < rhs.begin; });

    std::vector<Region> merged;
    for (const Region& region : snapshot_.regions) {
        if (!merged.empty() && merged.back().end == region.begin &&
            detail::same_mapping_identity(merged.back(), region)) {
            merged.back().end = region.end;
            merged.back().rss_kb += region.rss_kb;
            merged.back().pss_kb += region.pss_kb;
            merged.back().private_dirty_kb += region.private_dirty_kb;
        } else {
            merged.push_back(region);
        }
    }
    snapshot_.regions = std::move(merged);
}

}  // namespace mmv
