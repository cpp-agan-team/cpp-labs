#include "internal.hpp"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <sstream>
#include <string>
#include <sys/ptrace.h>
#include <sys/uio.h>

namespace mini_strace {
namespace detail {

RemoteBytes read_remote_bytes(pid_t pid, std::uint64_t address, std::size_t max_bytes) {
    RemoteBytes result;
    if (address == 0) {
        result.status = ArgReadStatus::NullPointer;
        return result;
    }
    if (max_bytes == 0) {
        result.status = ArgReadStatus::Ok;
        return result;
    }

    result.data.resize(max_bytes);
    iovec local {
        result.data.data(),
        result.data.size(),
    };
    iovec remote {
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(address)),
        result.data.size(),
    };

    errno = 0;
    const ssize_t nread = ::process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (nread > 0) {
        result.data.resize(static_cast<std::size_t>(nread));
        result.status = static_cast<std::size_t>(nread) < max_bytes ? ArgReadStatus::Truncated : ArgReadStatus::Ok;
        result.truncated = static_cast<std::size_t>(nread) < max_bytes;
        return result;
    }

    result.data.clear();
    result.error = errno_name(errno == 0 ? EFAULT : errno);

    const std::size_t word = sizeof(long);
    while (result.data.size() < max_bytes) {
        errno = 0;
        const unsigned long offset = static_cast<unsigned long>(result.data.size());
        const long value = ::ptrace(PTRACE_PEEKDATA, pid, reinterpret_cast<void*>(static_cast<std::uintptr_t>(address + offset)), nullptr);
        if (value == -1 && errno != 0) {
            break;
        }
        const auto* bytes = reinterpret_cast<const unsigned char*>(&value);
        const std::size_t remaining = max_bytes - result.data.size();
        const std::size_t copy = std::min(word, remaining);
        result.data.insert(result.data.end(), bytes, bytes + copy);
    }

    if (!result.data.empty()) {
        result.status = result.data.size() < max_bytes ? ArgReadStatus::Truncated : ArgReadStatus::Ok;
        result.truncated = result.data.size() < max_bytes;
        return result;
    }

    result.status = ArgReadStatus::Unreadable;
    if (errno != 0) {
        result.error = errno_name(errno);
    }
    return result;
}

DecodedArg read_remote_string_arg(pid_t pid, const std::string& name, std::uint64_t address, std::size_t limit) {
    DecodedArg arg;
    arg.name = name;
    arg.raw = address;
    if (address == 0) {
        arg.value = "NULL";
        arg.read_status = ArgReadStatus::NullPointer;
        return arg;
    }

    const auto bytes = read_remote_bytes(pid, address, limit + 1);
    arg.read_status = bytes.status;
    arg.read_error = bytes.error;
    if (bytes.status == ArgReadStatus::Unreadable || bytes.data.empty()) {
        arg.value = "<unreadable:" + (bytes.error.empty() ? std::string("EFAULT") : bytes.error) + ">";
        return arg;
    }

    std::string text;
    bool nul_seen = false;
    for (unsigned char ch : bytes.data) {
        if (ch == '\0') {
            nul_seen = true;
            break;
        }
        text.push_back(static_cast<char>(ch));
        if (text.size() >= limit) {
            break;
        }
    }
    arg.value = "\"" + escape_text(text) + (nul_seen ? "\"" : "...\"");
    if (!nul_seen || text.size() >= limit || bytes.truncated) {
        arg.read_status = ArgReadStatus::Truncated;
    }
    return arg;
}

DecodedArg read_remote_buffer_arg(pid_t pid, const std::string& name, std::uint64_t address, std::size_t limit) {
    DecodedArg arg;
    arg.name = name;
    arg.raw = address;
    if (address == 0) {
        arg.value = "NULL";
        arg.read_status = ArgReadStatus::NullPointer;
        return arg;
    }

    const auto bytes = read_remote_bytes(pid, address, limit);
    arg.read_status = bytes.status;
    arg.read_error = bytes.error;
    if (bytes.status == ArgReadStatus::Unreadable) {
        arg.value = "<unreadable:" + (bytes.error.empty() ? std::string("EFAULT") : bytes.error) + ">";
        return arg;
    }

    std::string text;
    text.reserve(bytes.data.size());
    for (unsigned char ch : bytes.data) {
        text.push_back(static_cast<char>(ch));
    }
    arg.value = "\"" + escape_text(text) + (bytes.truncated ? "...\"" : "\"");
    return arg;
}

std::string format_hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

}  // namespace detail
}  // namespace mini_strace
