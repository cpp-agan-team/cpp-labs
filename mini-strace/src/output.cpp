#include "internal.hpp"

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace mini_strace {
namespace detail {
namespace {

std::string format_ret(const SyscallEvent& event) {
    if (event.is_error) {
        return "-1 " + event.errno_name + " (" + event.errno_message + ")";
    }
    if (event.name == "mmap" || event.name == "brk") {
        return format_hex(static_cast<std::uint64_t>(event.raw_ret));
    }
    return std::to_string(event.raw_ret);
}

std::string format_duration(std::uint64_t ns) {
    std::ostringstream out;
    out << '<' << std::fixed << std::setprecision(6) << (static_cast<double>(ns) / 1000000000.0)
        << '>';
    return out.str();
}

std::string args_text(const SyscallEvent& event, bool raw) {
    std::ostringstream out;
    if (raw) {
        for (std::size_t i = 0; i < event.raw_args.size(); ++i) {
            if (i != 0) {
                out << ", ";
            }
            out << format_hex(event.raw_args[i]);
        }
        return out.str();
    }
    for (std::size_t i = 0; i < event.decoded_args.size(); ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << event.decoded_args[i].value;
    }
    return out.str();
}

std::string evidence_text(const std::vector<std::string>& evidence) {
    std::ostringstream out;
    for (std::size_t i = 0; i < evidence.size(); ++i) {
        if (i != 0) {
            out << ';';
        }
        out << evidence[i];
    }
    return out.str();
}

void write_json_string(std::ostream& out, const std::string& key, const std::string& value) {
    out << '"' << key << "\":\"" << escape_json(value) << '"';
}

}  // namespace

std::string format_event_text(const SyscallEvent& event, bool raw, bool show_state,
                              bool prefix_pid) {
    std::ostringstream out;
    if (prefix_pid) {
        out << "[pid " << event.pid << "] ";
    }
    out << event.name << '(' << args_text(event, raw) << ") = " << format_ret(event) << ' '
        << format_duration(event.duration_ns);
    if (show_state && event.fd_context) {
        out << " [fd=" << event.fd_context->fd;
        if (!event.fd_context->kind.empty()) {
            out << " kind=" << escape_text(event.fd_context->kind);
        }
        if (!event.fd_context->path.empty()) {
            out << " path=" << escape_text(event.fd_context->path);
        }
        if (!event.fd_context->peer.empty()) {
            out << " peer=" << escape_text(event.fd_context->peer);
        }
        if (event.fd_context->close_on_exec) {
            out << " cloexec=true";
        }
        out << ']';
    }
    if (show_state && event.vma_context) {
        out << " [mapping " << format_hex(event.vma_context->begin) << '-'
            << format_hex(event.vma_context->end);
        if (!event.vma_context->perms.empty()) {
            out << " perms=" << escape_text(event.vma_context->perms);
        }
        if (!event.vma_context->source.empty()) {
            out << " source=" << escape_text(event.vma_context->source);
        }
        out << ']';
    }
    if (event.injected) {
        out << " [injected " << event.injected_errno_name << ']';
    }
    if (event.seccomp_context) {
        out << " [seccomp action=" << event.seccomp_context->action
            << " ret_data=" << event.seccomp_context->ret_data << ']';
    }
    if (event.diagnosis) {
        out << " [diagnosis=" << event.diagnosis->category
            << " confidence=" << event.diagnosis->confidence
            << " evidence=" << evidence_text(event.diagnosis->evidence);
        if (!event.diagnosis->hint.empty()) {
            out << " hint=\"" << escape_text(event.diagnosis->hint) << '"';
        }
        out << ']';
    }
    return out.str();
}

std::string format_event_json(const SyscallEvent& event) {
    std::ostringstream out;
    out << '{';
    write_json_string(out, "type", "syscall");
    out << ",\"pid\":" << event.pid << ",\"tid\":" << event.tid << ",\"seq\":" << event.sequence;
    out << ",\"name\":\"" << escape_json(event.name) << "\",\"nr\":" << event.nr;
    out << ",\"args\":[";
    for (std::size_t i = 0; i < event.decoded_args.size(); ++i) {
        if (i != 0) {
            out << ',';
        }
        const auto& arg = event.decoded_args[i];
        out << "{\"name\":\"" << escape_json(arg.name) << "\",\"value\":\""
            << escape_json(arg.value) << "\",\"raw\":\"" << format_hex(arg.raw) << "\"}";
    }
    out << "],\"raw_args\":[";
    for (std::size_t i = 0; i < event.raw_args.size(); ++i) {
        if (i != 0) {
            out << ',';
        }
        out << '"' << format_hex(event.raw_args[i]) << '"';
    }
    out << ']';
    out << ",\"ret\":" << (event.is_error ? -1 : event.raw_ret) << ",\"raw_ret\":" << event.raw_ret;
    if (event.is_error) {
        out << ",\"error\":{\"name\":\"" << event.errno_name << "\",\"value\":" << event.errno_value
            << ",\"message\":\"" << escape_json(event.errno_message) << "\"}";
    } else {
        out << ",\"error\":null";
    }
    out << ",\"duration_ns\":" << event.duration_ns;
    if (event.fd_context) {
        out << ",\"fd_context\":{\"fd\":" << event.fd_context->fd
            << ",\"known\":" << (event.fd_context->known ? "true" : "false");
        if (!event.fd_context->kind.empty()) {
            out << ",\"kind\":\"" << escape_json(event.fd_context->kind) << "\"";
        }
        if (!event.fd_context->path.empty()) {
            out << ",\"path\":\"" << escape_json(event.fd_context->path) << "\"";
        }
        if (!event.fd_context->peer.empty()) {
            out << ",\"peer\":\"" << escape_json(event.fd_context->peer) << "\"";
        }
        if (!event.fd_context->source.empty()) {
            out << ",\"source\":\"" << escape_json(event.fd_context->source) << "\"";
        }
        out << ",\"close_on_exec\":" << (event.fd_context->close_on_exec ? "true" : "false");
        out << '}';
    }
    if (event.vma_context) {
        out << ",\"vma_context\":{\"begin\":\"" << format_hex(event.vma_context->begin)
            << "\",\"end\":\"" << format_hex(event.vma_context->end)
            << "\",\"known\":" << (event.vma_context->known ? "true" : "false");
        if (!event.vma_context->perms.empty()) {
            out << ",\"perms\":\"" << escape_json(event.vma_context->perms) << "\"";
        }
        if (!event.vma_context->source.empty()) {
            out << ",\"source\":\"" << escape_json(event.vma_context->source) << "\"";
        }
        out << '}';
    }
    if (event.injected) {
        out << ",\"injection\":{\"errno\":\"" << escape_json(event.injected_errno_name)
            << "\",\"value\":" << event.injected_errno_value << "}";
    }
    if (event.seccomp_context) {
        out << ",\"seccomp_context\":{\"ptrace_event\":"
            << (event.seccomp_context->ptrace_event ? "true" : "false") << ",\"action\":\""
            << escape_json(event.seccomp_context->action)
            << "\",\"ret_data\":" << event.seccomp_context->ret_data << "}";
    }
    if (event.diagnosis) {
        out << ",\"diagnosis\":{\"category\":\"" << escape_json(event.diagnosis->category)
            << "\",\"confidence\":\"" << escape_json(event.diagnosis->confidence)
            << "\",\"evidence\":[";
        for (std::size_t i = 0; i < event.diagnosis->evidence.size(); ++i) {
            if (i != 0) {
                out << ',';
            }
            out << '"' << escape_json(event.diagnosis->evidence[i]) << '"';
        }
        out << "],\"hint\":\"" << escape_json(event.diagnosis->hint) << "\"}";
    }
    out << '}';
    return out.str();
}

}  // namespace detail
}  // namespace mini_strace
