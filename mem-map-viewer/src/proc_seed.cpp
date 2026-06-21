#include "internal.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <sys/uio.h>

namespace mmv {
namespace {

bool parse_range(const std::string& text, uint64_t* begin, uint64_t* end) {
    size_t dash = text.find('-');
    if (dash == std::string::npos) {
        return false;
    }
    std::optional<uint64_t> parsed_begin = detail::parse_hex(text.substr(0, dash));
    std::optional<uint64_t> parsed_end = detail::parse_hex(text.substr(dash + 1));
    if (!parsed_begin || !parsed_end || *parsed_begin >= *parsed_end) {
        return false;
    }
    *begin = *parsed_begin;
    *end = *parsed_end;
    return true;
}

Perms parse_perms(const std::string& text) {
    Perms perms;
    if (text.size() >= 4) {
        perms.read = text[0] == 'r';
        perms.write = text[1] == 'w';
        perms.exec = text[2] == 'x';
        perms.shared = text[3] == 's';
    }
    return perms;
}

uint64_t parse_device(const std::string& text) {
    size_t colon = text.find(':');
    if (colon == std::string::npos) {
        return 0;
    }
    std::optional<uint64_t> major = detail::parse_hex(text.substr(0, colon));
    std::optional<uint64_t> minor = detail::parse_hex(text.substr(colon + 1));
    if (!major || !minor) {
        return 0;
    }
    return (*major << 32U) | *minor;
}

std::optional<Region> parse_maps_line(const std::string& line) {
    std::istringstream input(line);
    std::string range;
    std::string perms_text;
    std::string offset_text;
    std::string device_text;
    std::string inode_text;
    if (!(input >> range >> perms_text >> offset_text >> device_text >> inode_text)) {
        return std::nullopt;
    }

    Region region;
    if (!parse_range(range, &region.begin, &region.end)) {
        return std::nullopt;
    }
    region.perms = parse_perms(perms_text);
    region.source.offset = detail::parse_hex(offset_text).value_or(0);
    region.source.device = parse_device(device_text);
    region.source.inode = detail::parse_u64(inode_text).value_or(0);
    region.provenance = "seed";

    std::string path;
    std::getline(input, path);
    path = detail::trim(path);
    constexpr const char* kDeletedSuffix = " (deleted)";
    if (detail::ends_with(path, kDeletedSuffix)) {
        region.source.deleted = true;
        path.resize(path.size() - std::strlen(kDeletedSuffix));
    }
    if (!path.empty()) {
        if (path.front() == '[' && path.back() == ']') {
            region.label = path;
        } else {
            region.source.path = path;
            region.label = path;
        }
    }
    region.kind = detail::classify_region(region);
    return region;
}

bool is_maps_header(const std::string& line) {
    std::string first;
    std::istringstream input(line);
    input >> first;
    uint64_t begin = 0;
    uint64_t end = 0;
    return parse_range(first, &begin, &end);
}

void apply_smaps_value(const std::string& line, Region* region) {
    size_t colon = line.find(':');
    if (colon == std::string::npos) {
        return;
    }
    std::string key = line.substr(0, colon);
    std::string rest = detail::trim(line.substr(colon + 1));
    std::istringstream input(rest);
    uint64_t value = 0;
    input >> value;
    if (key == "Rss") {
        region->rss_kb = value;
    } else if (key == "Pss") {
        region->pss_kb = value;
    } else if (key == "Private_Dirty") {
        region->private_dirty_kb = value;
    }
}

void read_smaps(int pid, Snapshot* snapshot) {
    std::ostringstream path;
    path << "/proc/" << pid << "/smaps";
    std::ifstream input(path.str());
    if (!input) {
        return;
    }

    Region* current = nullptr;
    std::string line;
    while (std::getline(input, line)) {
        if (is_maps_header(line)) {
            std::optional<Region> parsed = parse_maps_line(line);
            current = nullptr;
            if (!parsed) {
                continue;
            }
            auto it = std::find_if(
                snapshot->regions.begin(), snapshot->regions.end(), [&](const Region& region) {
                    return region.begin == parsed->begin && region.end == parsed->end;
                });
            if (it != snapshot->regions.end()) {
                current = &*it;
            }
            continue;
        }
        if (current) {
            apply_smaps_value(line, current);
        }
    }
}

RegionProbe probe_region(int pid, const Region& region) {
    RegionProbe probe;
    probe.attempted = true;
    if (!region.perms.read || region.begin >= region.end) {
        return probe;
    }

    std::array<unsigned char, 16> buffer{};
    iovec local{};
    local.iov_base = buffer.data();
    local.iov_len = buffer.size();
    iovec remote{};
    remote.iov_base = reinterpret_cast<void*>(region.begin);
    remote.iov_len = buffer.size();
    ssize_t n = ::process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n <= 0) {
        return probe;
    }
    probe.readable = true;
    probe.bytes_read = static_cast<size_t>(n);
    probe.has_elf_header =
        n >= 4 && buffer[0] == 0x7f && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F';
    return probe;
}

}  // namespace

Snapshot read_proc_snapshot(int pid, const SnapshotOptions& options) {
    std::ostringstream path;
    path << "/proc/" << pid << "/maps";
    std::ifstream input(path.str());
    if (!input) {
        throw std::runtime_error("cannot open " + path.str() + ": " + std::strerror(errno));
    }

    Snapshot snapshot;
    snapshot.pid = pid;
    snapshot.timestamp_ns = detail::now_ns();

    std::string line;
    while (std::getline(input, line)) {
        std::optional<Region> region = parse_maps_line(line);
        if (region) {
            snapshot.regions.push_back(std::move(*region));
        }
    }

    if (options.with_smaps) {
        read_smaps(pid, &snapshot);
    }
    if (options.probe_memory) {
        for (Region& region : snapshot.regions) {
            region.probe = probe_region(pid, region);
        }
    }
    return snapshot;
}

}  // namespace mmv
