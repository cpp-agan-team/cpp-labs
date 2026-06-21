#include "internal.hpp"

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <istream>
#include <regex>
#include <sstream>
#include <stdexcept>

namespace mmv {
namespace {

std::string read_all(std::istream& input) {
    std::ostringstream out;
    out << input.rdbuf();
    return out.str();
}

uint64_t parse_hex_field(const std::string& object, const std::string& name) {
    std::regex pattern("\"" + name + "\":\"0x([0-9a-fA-F]+)\"");
    std::smatch match;
    if (!std::regex_search(object, match, pattern)) {
        return 0;
    }
    return detail::parse_hex(match[1].str()).value_or(0);
}

uint64_t parse_u64_field(const std::string& object, const std::string& name) {
    std::regex pattern("\"" + name + "\":([0-9]+)");
    std::smatch match;
    if (!std::regex_search(object, match, pattern)) {
        return 0;
    }
    return detail::parse_u64(match[1].str()).value_or(0);
}

// Signed integer field (e.g. "fd":-1). parse_u64_field's [0-9]+ pattern drops the
// sign, which would silently turn an anonymous mapping's fd=-1 into fd=0 (a valid
// stdin descriptor) on round-trip, so signed fields need their own parser.
int parse_int_field(const std::string& object, const std::string& name, int fallback) {
    std::regex pattern("\"" + name + "\":(-?[0-9]+)");
    std::smatch match;
    if (!std::regex_search(object, match, pattern)) {
        return fallback;
    }
    errno = 0;
    char* end = nullptr;
    long value = std::strtol(match[1].str().c_str(), &end, 10);
    if (errno != 0 || value < INT_MIN || value > INT_MAX) {
        return fallback;
    }
    return static_cast<int>(value);
}

bool parse_bool_field(const std::string& object, const std::string& name) {
    std::regex pattern("\"" + name + "\":(true|false)");
    std::smatch match;
    if (!std::regex_search(object, match, pattern)) {
        return false;
    }
    return match[1].str() == "true";
}

std::string parse_string_field(const std::string& object, const std::string& name) {
    std::regex pattern("\"" + name + "\":\"([^\"]*)\"");
    std::smatch match;
    if (!std::regex_search(object, match, pattern)) {
        return {};
    }
    return match[1].str();
}

Perms parse_perms_field(const std::string& object) {
    std::string text = parse_string_field(object, "perms");
    Perms perms;
    if (text.size() >= 4) {
        perms.read = text[0] == 'r';
        perms.write = text[1] == 'w';
        perms.exec = text[2] == 'x';
        perms.shared = text[3] == 's';
    }
    return perms;
}

RegionKind parse_kind(const std::string& value) {
    if (value == "text") {
        return RegionKind::Text;
    }
    if (value == "data") {
        return RegionKind::Data;
    }
    if (value == "heap") {
        return RegionKind::Heap;
    }
    if (value == "stack") {
        return RegionKind::Stack;
    }
    if (value == "thread_stack") {
        return RegionKind::ThreadStack;
    }
    if (value == "library") {
        return RegionKind::SharedLibrary;
    }
    if (value == "file") {
        return RegionKind::FileMapping;
    }
    if (value == "anonymous") {
        return RegionKind::Anonymous;
    }
    if (value == "vdso") {
        return RegionKind::Vdso;
    }
    if (value == "vvar") {
        return RegionKind::Vvar;
    }
    if (value == "vsyscall") {
        return RegionKind::Vsyscall;
    }
    return RegionKind::Unknown;
}

}  // namespace

Snapshot parse_snapshot_json(std::istream& input) {
    std::string text = read_all(input);
    Snapshot snapshot;
    snapshot.pid = static_cast<int>(parse_u64_field(text, "pid"));
    snapshot.timestamp_ns = parse_u64_field(text, "timestamp_ns");

    std::regex region_pattern(
        "\\{\"begin\":\"0x[0-9a-fA-F]+\".*?\\}\\,?\\s*(?=\\{\"begin\"|\\]\\})");
    auto begin = std::sregex_iterator(text.begin(), text.end(), region_pattern);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string object = it->str();
        Region region;
        region.begin = parse_hex_field(object, "begin");
        region.end = parse_hex_field(object, "end");
        region.kind = parse_kind(parse_string_field(object, "kind"));
        region.perms = parse_perms_field(object);
        region.rss_kb = parse_u64_field(object, "rss_kb");
        region.pss_kb = parse_u64_field(object, "pss_kb");
        region.private_dirty_kb = parse_u64_field(object, "private_dirty_kb");
        region.label = parse_string_field(object, "label");
        region.provenance = parse_string_field(object, "provenance");
        if (region.provenance.empty()) {
            region.provenance = "unknown";
        }
        region.source.fd = parse_int_field(object, "fd", -1);
        region.source.inode = parse_u64_field(object, "inode");
        region.source.device = parse_u64_field(object, "device");
        region.source.offset = parse_u64_field(object, "offset");
        region.source.path = parse_string_field(object, "path");
        region.source.deleted = parse_bool_field(object, "deleted");
        if (region.begin < region.end) {
            snapshot.regions.push_back(std::move(region));
        }
    }
    if (snapshot.regions.empty() && text.find("\"regions\"") == std::string::npos) {
        throw std::runtime_error("input is not a mem-map-viewer snapshot JSON");
    }
    return snapshot;
}

}  // namespace mmv
