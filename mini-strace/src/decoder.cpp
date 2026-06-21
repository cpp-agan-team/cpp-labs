#include "decoder_internal.hpp"

#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

namespace mini_strace {
namespace detail {
namespace {

void add_raw_args(SyscallEvent& event) {
    for (std::size_t i = 0; i < event.raw_args.size(); ++i) {
        add_arg(event, "arg" + std::to_string(i), format_hex(event.raw_args[i]), event.raw_args[i]);
    }
}

bool needs_state_decode(const std::string& name) {
    return name == "open" || name == "openat" || name == "creat" || name == "openat2" ||
           name == "connect" || name == "accept" || name == "accept4";
}

enum class MetadataArgFormat {
    Decimal,
    Fd,
    Hex,
    NullableHex,
    Buffer,
    Path,
    StringArray,
    OpenFlags,
    MmapProt,
    MmapFlags,
    PollFds,
};

struct MetadataArg {
    const char* name;
    MetadataArgFormat format;
};

struct SyscallMetadata {
    const char* name;
    std::vector<MetadataArg> args;
    bool generic_decode;
};

const std::vector<SyscallMetadata>& syscall_metadata() {
    static const std::vector<SyscallMetadata> specs = {
        {"read",
         {{"fd", MetadataArgFormat::Fd},
          {"buf", MetadataArgFormat::Buffer},
          {"count", MetadataArgFormat::Decimal}},
         false},
        {"write",
         {{"fd", MetadataArgFormat::Fd},
          {"buf", MetadataArgFormat::Buffer},
          {"count", MetadataArgFormat::Decimal}},
         false},
        {"openat",
         {{"dirfd", MetadataArgFormat::Fd},
          {"pathname", MetadataArgFormat::Path},
          {"flags", MetadataArgFormat::OpenFlags},
          {"mode", MetadataArgFormat::Decimal}},
         false},
        {"close", {{"fd", MetadataArgFormat::Fd}}, true},
        {"mmap",
         {{"addr", MetadataArgFormat::NullableHex},
          {"length", MetadataArgFormat::Decimal},
          {"prot", MetadataArgFormat::MmapProt},
          {"flags", MetadataArgFormat::MmapFlags},
          {"fd", MetadataArgFormat::Fd},
          {"offset", MetadataArgFormat::Decimal}},
         false},
        {"munmap",
         {{"addr", MetadataArgFormat::Hex}, {"length", MetadataArgFormat::Decimal}},
         true},
        {"brk", {{"addr", MetadataArgFormat::NullableHex}}, true},
        {"execve",
         {{"pathname", MetadataArgFormat::Path},
          {"argv", MetadataArgFormat::StringArray},
          {"envp", MetadataArgFormat::Hex}},
         false},
        {"poll",
         {{"fds", MetadataArgFormat::PollFds},
          {"nfds", MetadataArgFormat::Decimal},
          {"timeout", MetadataArgFormat::Decimal}},
         false},
        {"fsync", {{"fd", MetadataArgFormat::Fd}}, true},
        {"fdatasync", {{"fd", MetadataArgFormat::Fd}}, true},
        {"getpid", {}, true},
        {"gettid", {}, true},
        {"getppid", {}, true},
        {"getuid", {}, true},
        {"getgid", {}, true},
        {"geteuid", {}, true},
        {"getegid", {}, true},
        {"sched_yield", {}, true},
        {"pause", {}, true},
        {"restart_syscall", {}, true},
    };
    return specs;
}

const SyscallMetadata* find_syscall_metadata(const std::string& name) {
    for (const auto& spec : syscall_metadata()) {
        if (name == spec.name) {
            return &spec;
        }
    }
    return nullptr;
}

std::string format_metadata_arg(std::uint64_t value, MetadataArgFormat format) {
    switch (format) {
        case MetadataArgFormat::Decimal:
            return std::to_string(value);
        case MetadataArgFormat::Fd:
            return std::to_string(static_cast<long long>(value));
        case MetadataArgFormat::Hex:
            return format_hex(value);
        case MetadataArgFormat::NullableHex:
            return value == 0 ? "NULL" : format_hex(value);
        case MetadataArgFormat::Buffer:
        case MetadataArgFormat::Path:
        case MetadataArgFormat::StringArray:
        case MetadataArgFormat::OpenFlags:
        case MetadataArgFormat::MmapProt:
        case MetadataArgFormat::MmapFlags:
        case MetadataArgFormat::PollFds:
            return format_hex(value);
    }
    return format_hex(value);
}

bool decode_basic_metadata_event(SyscallEvent& event) {
    const auto* spec = find_syscall_metadata(event.name);
    if (spec == nullptr || !spec->generic_decode) {
        return false;
    }
    for (std::size_t i = 0; i < spec->args.size(); ++i) {
        add_arg(event, spec->args[i].name,
                format_metadata_arg(event.raw_args[i], spec->args[i].format), event.raw_args[i]);
    }
    return true;
}

}  // namespace

std::uint64_t now_ns() {
    timespec ts{};
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ULL +
           static_cast<std::uint64_t>(ts.tv_nsec);
}

std::string escape_text(const std::string& input) {
    std::ostringstream out;
    for (unsigned char ch : input) {
        switch (ch) {
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            case '\\':
                out << "\\\\";
                break;
            case '"':
                out << "\\\"";
                break;
            default:
                if (ch < 0x20 || ch >= 0x7f) {
                    out << "\\x" << std::hex << std::setw(2) << std::setfill('0')
                        << static_cast<int>(ch) << std::dec;
                } else {
                    out << static_cast<char>(ch);
                }
                break;
        }
    }
    return out.str();
}

std::string escape_json(const std::string& input) {
    std::ostringstream out;
    for (unsigned char ch : input) {
        switch (ch) {
            case '\b':
                out << "\\b";
                break;
            case '\f':
                out << "\\f";
                break;
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            case '\\':
                out << "\\\\";
                break;
            case '"':
                out << "\\\"";
                break;
            default:
                if (ch < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(ch) << std::dec;
                } else {
                    out << static_cast<char>(ch);
                }
                break;
        }
    }
    return out.str();
}

void decode_event(SyscallEvent& event, const TraceOptions& options) {
    event.name = syscall_name(event.nr);

    const std::string& name = event.name;
    if (options.raw) {
        event.decoded_args.clear();
        add_raw_args(event);
        return;
    }
    if ((name == "execve" || name == "execveat") && !event.decoded_args.empty()) {
        return;
    }
    event.decoded_args.clear();

    if (decode_basic_metadata_event(event)) {
        return;
    }
    if (decode_file_event(event, options)) {
        return;
    }
    if (decode_memory_event(event)) {
        return;
    }
    if (decode_net_event(event, options)) {
        return;
    }
    if (decode_seccomp_event(event)) {
        return;
    }
    if (decode_process_event(event, options)) {
        return;
    }
    if (decode_poll_epoll_event(event)) {
        return;
    }

    add_raw_args(event);
}

void decode_event_for_state(SyscallEvent& event, const TraceOptions& options) {
    event.name = syscall_name(event.nr);
    if (options.raw || !needs_state_decode(event.name)) {
        return;
    }
    if ((event.name == "execve" || event.name == "execveat") && !event.decoded_args.empty()) {
        return;
    }
    event.decoded_args.clear();
    if (decode_file_event(event, options)) {
        return;
    }
    (void)decode_net_event(event, options);
}

void predecode_entry_event(SyscallEvent& event, const TraceOptions& options) {
    event.name = syscall_name(event.nr);
    if (options.raw) {
        return;
    }
    predecode_process_entry_event(event, options);
}

}  // namespace detail
}  // namespace mini_strace
