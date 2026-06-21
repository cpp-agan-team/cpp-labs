#pragma once

#include "internal.hpp"

#include <cstdint>
#include <string>
#include <sys/types.h>
#include <utility>

namespace mini_strace {
namespace detail {

inline void add_arg(SyscallEvent& event, std::string name, std::string value, std::uint64_t raw) {
    DecodedArg arg;
    arg.name = std::move(name);
    arg.value = std::move(value);
    arg.raw = raw;
    event.decoded_args.push_back(std::move(arg));
}

std::string format_open_flags(std::uint64_t flags);
std::string format_mmap_prot(std::uint64_t prot);
std::string format_mmap_flags(std::uint64_t flags);
std::string format_sockaddr(pid_t pid, std::uint64_t address, std::uint64_t length);

void decode_event(SyscallEvent& event, const TraceOptions& options);
void decode_event_for_state(SyscallEvent& event, const TraceOptions& options);
bool decode_file_event(SyscallEvent& event, const TraceOptions& options);
bool decode_memory_event(SyscallEvent& event);
bool decode_net_event(SyscallEvent& event, const TraceOptions& options);
bool decode_poll_epoll_event(SyscallEvent& event);
bool decode_process_event(SyscallEvent& event, const TraceOptions& options);
bool decode_seccomp_event(SyscallEvent& event);
void predecode_process_entry_event(SyscallEvent& event, const TraceOptions& options);
void predecode_entry_event(SyscallEvent& event, const TraceOptions& options);

}  // namespace detail
}  // namespace mini_strace
