#pragma once

#include "mem_map_viewer.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace mmv::detail {

std::string trim(std::string value);
bool starts_with(const std::string& value, const std::string& prefix);
bool ends_with(const std::string& value, const std::string& suffix);
std::optional<uint64_t> parse_u64(const std::string& value, int base = 10);
std::optional<int64_t> parse_i64(const std::string& value, int base = 10);
std::optional<uint64_t> parse_hex(const std::string& value);
uint64_t now_ns();
std::string format_size(uint64_t bytes);
std::string source_key(const Region& region);
std::string region_key(const Region& region);
uint64_t region_size(const Region& region);
RegionKind classify_region(const Region& region);
bool same_mapping_identity(const Region& lhs, const Region& rhs);
std::vector<std::string> split_ws(const std::string& line);

class RegionIndex {
public:
    explicit RegionIndex(const std::vector<Region>& regions);

    const Region* find(uint64_t address) const;

private:
    std::vector<const Region*> regions_;
};

}  // namespace mmv::detail

namespace mmv {

MappingSource resolve_mapping_fd(int pid, int fd, uint64_t offset);

}  // namespace mmv
