#pragma once

#include "mem_map_viewer.hpp"

namespace mmv {

class VmaModel {
public:
    explicit VmaModel(Snapshot seed = {});

    void apply(const MapEvent& event);
    Snapshot snapshot() const;

private:
    void map_region(Region region);
    void unmap_range(uint64_t begin, uint64_t end);
    void protect_range(uint64_t begin, uint64_t end, const Perms& perms);
    void remap_range(uint64_t old_begin, uint64_t old_size, uint64_t new_begin, uint64_t new_size,
                     uint64_t flags);
    void apply_brk(uint64_t new_brk);
    void sort_and_merge();

    Snapshot snapshot_;
    uint64_t heap_base_ = 0;
};

}  // namespace mmv
