#include "internal.hpp"

#include <algorithm>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>

namespace mmv {
namespace {

std::string read_text_file(const std::string& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("cannot open " + path);
    }
    std::ostringstream out;
    out << input.rdbuf();
    return detail::trim(out.str());
}

uint64_t read_u64_file(const std::string& path) {
    std::string text = read_text_file(path);
    std::optional<uint64_t> value = detail::parse_u64(text);
    if (!value) {
        throw std::runtime_error("invalid integer in " + path);
    }
    return *value;
}

std::map<std::string, uint64_t> read_kv_file(const std::string& path) {
    std::ifstream input(path);
    std::map<std::string, uint64_t> values;
    if (!input) {
        return values;
    }

    std::string key;
    uint64_t value = 0;
    while (input >> key >> value) {
        values[key] = value;
    }
    return values;
}

std::string self_cgroup_path() {
    std::ifstream input("/proc/self/cgroup");
    std::string line;
    while (std::getline(input, line)) {
        if (!detail::starts_with(line, "0::")) {
            continue;
        }
        std::string relative = line.substr(3);
        if (relative.empty() || relative == "/") {
            return "/sys/fs/cgroup";
        }
        return "/sys/fs/cgroup" + relative;
    }
    return "/sys/fs/cgroup";
}

void parse_psi_line(const std::string& line, PsiLine* out) {
    std::istringstream input(line);
    std::string kind;
    input >> kind;
    std::string field;
    while (input >> field) {
        size_t eq = field.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        std::string name = field.substr(0, eq);
        std::string value = field.substr(eq + 1);
        if (name == "avg10") {
            out->avg10 = std::strtod(value.c_str(), nullptr);
        } else if (name == "avg60") {
            out->avg60 = std::strtod(value.c_str(), nullptr);
        } else if (name == "avg300") {
            out->avg300 = std::strtod(value.c_str(), nullptr);
        } else if (name == "total") {
            out->total = detail::parse_u64(value).value_or(0);
        }
    }
}

void read_pressure(const std::string& path, CgroupMemoryHealth* health) {
    std::ifstream input(path + "/memory.pressure");
    if (!input) {
        return;
    }
    health->has_pressure = true;
    std::string line;
    while (std::getline(input, line)) {
        if (detail::starts_with(line, "some ")) {
            parse_psi_line(line, &health->some);
        } else if (detail::starts_with(line, "full ")) {
            parse_psi_line(line, &health->full);
        }
    }
}

double compute_risk(const CgroupMemoryHealth& health) {
    if (!health.has_limit || health.max_bytes == 0) {
        return 0.0;
    }
    const double usage = std::min(1.0, health.usage_ratio);
    const double stall = std::min(1.0, health.full.avg10 / 100.0);
    const double history = health.oom_kill_events > 0 ? 0.3 : 0.0;
    return std::min(1.0, 0.6 * usage + 0.4 * stall + history);
}

}  // namespace

CgroupMemoryHealth read_cgroup_memory_health(const std::string& path) {
    CgroupMemoryHealth health;
    const std::string resolved_path = path == "self" ? self_cgroup_path() : path;
    health.path = resolved_path;
    health.current_bytes = read_u64_file(resolved_path + "/memory.current");

    std::string max_text = read_text_file(resolved_path + "/memory.max");
    if (max_text != "max") {
        health.max_bytes = detail::parse_u64(max_text).value_or(0);
        health.has_limit = health.max_bytes > 0;
    }
    if (health.has_limit) {
        health.usage_ratio =
            static_cast<double>(health.current_bytes) / static_cast<double>(health.max_bytes);
    }

    std::map<std::string, uint64_t> stat = read_kv_file(resolved_path + "/memory.stat");
    health.anon_bytes = stat["anon"];
    health.file_bytes = stat["file"];
    health.kernel_stack_bytes = stat["kernel_stack"];

    std::map<std::string, uint64_t> events = read_kv_file(resolved_path + "/memory.events");
    health.oom_events = events["oom"];
    health.oom_kill_events = events["oom_kill"];

    read_pressure(resolved_path, &health);
    health.oom_risk = compute_risk(health);
    return health;
}

}  // namespace mmv
