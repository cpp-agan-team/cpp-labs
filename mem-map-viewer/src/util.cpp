#include "internal.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <sstream>

namespace mmv::detail {

std::string trim(std::string value) {
    const char* whitespace = " \t\r\n";
    size_t begin = value.find_first_not_of(whitespace);
    if (begin == std::string::npos) {
        return {};
    }
    size_t end = value.find_last_not_of(whitespace);
    return value.substr(begin, end - begin + 1);
}

bool starts_with(const std::string& value, const std::string& prefix) {
    return value.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), value.begin());
}

bool ends_with(const std::string& value, const std::string& suffix) {
    return suffix.size() <= value.size() &&
           std::equal(suffix.rbegin(), suffix.rend(), value.rbegin());
}

std::optional<uint64_t> parse_u64(const std::string& value, int base) {
    std::string text = trim(value);
    if (text.empty()) {
        return std::nullopt;
    }
    char* end = nullptr;
    unsigned long long parsed = std::strtoull(text.c_str(), &end, base);
    if (end == text.c_str()) {
        return std::nullopt;
    }
    return static_cast<uint64_t>(parsed);
}

std::optional<int64_t> parse_i64(const std::string& value, int base) {
    std::string text = trim(value);
    if (text.empty()) {
        return std::nullopt;
    }
    char* end = nullptr;
    long long parsed = std::strtoll(text.c_str(), &end, base);
    if (end == text.c_str()) {
        return std::nullopt;
    }
    return static_cast<int64_t>(parsed);
}

std::optional<uint64_t> parse_hex(const std::string& value) {
    return parse_u64(value, 16);
}

uint64_t now_ns() {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

std::string format_size(uint64_t bytes) {
    static constexpr std::array<const char*, 5> kUnits = {"B", "K", "M", "G", "T"};
    double value = static_cast<double>(bytes);
    size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < std::size(kUnits)) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream out;
    if (unit == 0 || value >= 10.0) {
        out << static_cast<uint64_t>(value);
    } else {
        out << std::fixed << std::setprecision(1) << value;
    }
    out << kUnits[unit];
    return out.str();
}

uint64_t region_size(const Region& region) {
    return region.end > region.begin ? region.end - region.begin : 0;
}

std::string source_key(const Region& region) {
    if (!region.source.path.empty()) {
        return region.source.path;
    }
    if (!region.label.empty()) {
        return region.label;
    }
    if (region.source.inode != 0) {
        std::ostringstream out;
        out << "inode:" << region.source.inode;
        return out.str();
    }
    return "[anon]";
}

std::string region_key(const Region& region) {
    return std::string(kind_name(region.kind)) + ":" + source_key(region);
}

RegionKind classify_region(const Region& region) {
    const std::string& label = !region.label.empty() ? region.label : region.source.path;
    if (label == "[heap]") {
        return RegionKind::Heap;
    }
    if (label == "[stack]") {
        return RegionKind::Stack;
    }
    if (starts_with(label, "[stack:")) {
        return RegionKind::ThreadStack;
    }
    if (label == "[vdso]") {
        return RegionKind::Vdso;
    }
    if (label == "[vvar]") {
        return RegionKind::Vvar;
    }
    if (label == "[vsyscall]") {
        return RegionKind::Vsyscall;
    }
    if (!region.source.path.empty()) {
        if (region.perms.exec && region.source.offset == 0) {
            return RegionKind::Text;
        }
        if (region.source.path.find(".so") != std::string::npos ||
            starts_with(region.source.path, "/lib") ||
            starts_with(region.source.path, "/usr/lib")) {
            return RegionKind::SharedLibrary;
        }
        return RegionKind::FileMapping;
    }
    return RegionKind::Anonymous;
}

bool same_mapping_identity(const Region& lhs, const Region& rhs) {
    return lhs.kind == rhs.kind && lhs.perms.read == rhs.perms.read &&
           lhs.perms.write == rhs.perms.write && lhs.perms.exec == rhs.perms.exec &&
           lhs.perms.shared == rhs.perms.shared && lhs.source.inode == rhs.source.inode &&
           lhs.source.device == rhs.source.device && lhs.source.path == rhs.source.path &&
           lhs.label == rhs.label && lhs.provenance == rhs.provenance;
}

std::vector<std::string> split_ws(const std::string& line) {
    std::istringstream input(line);
    std::vector<std::string> fields;
    std::string field;
    while (input >> field) {
        fields.push_back(field);
    }
    return fields;
}

RegionIndex::RegionIndex(const std::vector<Region>& regions) {
    regions_.reserve(regions.size());
    for (const Region& region : regions) {
        if (region.begin < region.end) {
            regions_.push_back(&region);
        }
    }
    std::sort(regions_.begin(), regions_.end(), [](const Region* lhs, const Region* rhs) {
        if (lhs->begin != rhs->begin) {
            return lhs->begin < rhs->begin;
        }
        return lhs->end < rhs->end;
    });
}

const Region* RegionIndex::find(uint64_t address) const {
    auto it = std::upper_bound(
        regions_.begin(), regions_.end(), address,
        [](uint64_t value, const Region* region) { return value < region->begin; });
    if (it == regions_.begin()) {
        return nullptr;
    }
    --it;
    const Region* region = *it;
    if (region->begin <= address && address < region->end) {
        return region;
    }
    return nullptr;
}

}  // namespace mmv::detail

namespace mmv {

const char* kind_name(RegionKind kind) {
    switch (kind) {
        case RegionKind::Text:
            return "text";
        case RegionKind::Data:
            return "data";
        case RegionKind::Heap:
            return "heap";
        case RegionKind::Stack:
            return "stack";
        case RegionKind::ThreadStack:
            return "thread_stack";
        case RegionKind::SharedLibrary:
            return "library";
        case RegionKind::FileMapping:
            return "file";
        case RegionKind::Anonymous:
            return "anonymous";
        case RegionKind::Vdso:
            return "vdso";
        case RegionKind::Vvar:
            return "vvar";
        case RegionKind::Vsyscall:
            return "vsyscall";
        case RegionKind::Unknown:
            return "unknown";
    }
    return "unknown";
}

const char* event_type_name(MapEventType type) {
    switch (type) {
        case MapEventType::Mmap:
            return "mmap";
        case MapEventType::Munmap:
            return "munmap";
        case MapEventType::Mprotect:
            return "mprotect";
        case MapEventType::Brk:
            return "brk";
        case MapEventType::Mremap:
            return "mremap";
        case MapEventType::Exec:
            return "exec";
        case MapEventType::ProcSeed:
            return "proc_seed";
    }
    return "unknown";
}

std::string perms_string(const Perms& perms) {
    std::string out;
    out.push_back(perms.read ? 'r' : '-');
    out.push_back(perms.write ? 'w' : '-');
    out.push_back(perms.exec ? 'x' : '-');
    out.push_back(perms.shared ? 's' : 'p');
    return out;
}

}  // namespace mmv
