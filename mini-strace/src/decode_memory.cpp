#include "decoder_internal.hpp"

#include <cstdint>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <utility>
#include <vector>

namespace mini_strace {
namespace detail {
namespace {

std::string format_fd(std::uint64_t value) {
    return std::to_string(static_cast<long long>(value));
}

std::string flag_list(std::uint64_t value,
                      const std::vector<std::pair<std::uint64_t, const char*>>& flags,
                      std::uint64_t known) {
    std::vector<std::string> parts;
    for (const auto& flag : flags) {
        if ((value & flag.first) == flag.first) {
            parts.emplace_back(flag.second);
        }
    }
    const std::uint64_t unknown = value & ~known;
    if (unknown != 0) {
        parts.push_back(format_hex(unknown));
    }
    if (parts.empty()) {
        return "0";
    }
    std::ostringstream out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) {
            out << '|';
        }
        out << parts[i];
    }
    return out.str();
}

}  // namespace

std::string format_mmap_prot(std::uint64_t prot) {
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> flags = {
        {PROT_READ, "PROT_READ"},
        {PROT_WRITE, "PROT_WRITE"},
        {PROT_EXEC, "PROT_EXEC"},
    };
    for (const auto& flag : flags) {
        known |= flag.first;
    }
    if (prot == PROT_NONE) {
        return "PROT_NONE";
    }
    return flag_list(prot, flags, known);
}

std::string format_mmap_flags(std::uint64_t flags) {
    std::uint64_t known = 0;
    const std::vector<std::pair<std::uint64_t, const char*>> values = {
#ifdef MAP_SHARED
        {MAP_SHARED, "MAP_SHARED"},
#endif
#ifdef MAP_PRIVATE
        {MAP_PRIVATE, "MAP_PRIVATE"},
#endif
#ifdef MAP_FIXED
        {MAP_FIXED, "MAP_FIXED"},
#endif
#ifdef MAP_ANONYMOUS
        {MAP_ANONYMOUS, "MAP_ANONYMOUS"},
#endif
#ifdef MAP_POPULATE
        {MAP_POPULATE, "MAP_POPULATE"},
#endif
#ifdef MAP_STACK
        {MAP_STACK, "MAP_STACK"},
#endif
    };
    for (const auto& flag : values) {
        known |= flag.first;
    }
    return flag_list(flags, values, known);
}

bool decode_memory_event(SyscallEvent& event) {
    const std::string& name = event.name;
    if (name == "mmap") {
        add_arg(event, "addr", event.raw_args[0] == 0 ? "NULL" : format_hex(event.raw_args[0]),
                event.raw_args[0]);
        add_arg(event, "length", std::to_string(event.raw_args[1]), event.raw_args[1]);
        add_arg(event, "prot", format_mmap_prot(event.raw_args[2]), event.raw_args[2]);
        add_arg(event, "flags", format_mmap_flags(event.raw_args[3]), event.raw_args[3]);
        add_arg(event, "fd", format_fd(event.raw_args[4]), event.raw_args[4]);
        add_arg(event, "offset", std::to_string(event.raw_args[5]), event.raw_args[5]);
        return true;
    }
    if (name == "munmap") {
        add_arg(event, "addr", format_hex(event.raw_args[0]), event.raw_args[0]);
        add_arg(event, "length", std::to_string(event.raw_args[1]), event.raw_args[1]);
        return true;
    }
    if (name == "mprotect") {
        add_arg(event, "addr", format_hex(event.raw_args[0]), event.raw_args[0]);
        add_arg(event, "length", std::to_string(event.raw_args[1]), event.raw_args[1]);
        add_arg(event, "prot", format_mmap_prot(event.raw_args[2]), event.raw_args[2]);
        return true;
    }
    if (name == "brk") {
        add_arg(event, "addr", event.raw_args[0] == 0 ? "NULL" : format_hex(event.raw_args[0]),
                event.raw_args[0]);
        return true;
    }
    return false;
}

}  // namespace detail
}  // namespace mini_strace
