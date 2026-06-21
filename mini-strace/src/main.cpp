#include "mini_strace.hpp"

#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

void print_help(std::ostream& out) {
    out << "mini-strace: ptrace-based syscall tracer for x86_64 Linux\n\n"
        << "Usage:\n"
        << "  mini-strace [options] -- <command> [args...]\n"
        << "  mini-strace [options] <command> [args...]\n"
        << "  mini-strace --pid <pid> [options]\n\n"
        << "Options:\n"
        << "  --pid <pid>           Attach to an existing process\n"
        << "  --filter a,b,c        Only output selected syscall names\n"
        << "  --summary             Print count/error/latency summary at the end\n"
        << "  --diagnose            Print evidence-based diagnostics at the end\n"
        << "  --io-latency          Print fd/path/syscall I/O latency summary\n"
        << "  --slow-us <n>         Slow I/O threshold in microseconds (default 1000)\n"
        << "  --net                 Print network syscall and socket summary\n"
        << "  --explain-deny        Add evidence-based diagnosis to denied syscalls\n"
        << "  --process             Print process/resource syscall summary\n"
        << "  --json                Emit JSON Lines events\n"
        << "  --raw                 Do not decode syscall arguments\n"
        << "  --state               Include lightweight fd/VMA context\n"
        << "  --signals             Emit signal-delivery stops before forwarding them\n"
        << "  --lifecycle           Emit thread/process exit and signaled events\n"
        << "  --follow-fork, -f     Follow fork/vfork/clone children\n"
        << "  --seccomp-bpf         Use seccomp-BPF to stop only filtered syscalls\n"
        << "  --dump-seccomp        Dump generated/target classic BPF seccomp filters when "
           "visible\n"
        << "  --inject <spec>       Inject syscall error, e.g. write:error=EIO[:when=3]\n"
        << "  --strings <n>         Max bytes to read from tracee strings/buffers (default 64)\n"
        << "  --max-events <n>      Stop after n emitted events and detach\n"
        << "  --output <path|- >    Write tracer output to file or stdout (default stderr)\n"
        << "  --help                Show this help\n";
}

std::vector<std::string> split_commas(const std::string& text) {
    std::vector<std::string> result;
    std::string current;
    std::istringstream in(text);
    while (std::getline(in, current, ',')) {
        if (!current.empty()) {
            result.push_back(current);
        }
    }
    return result;
}

std::size_t parse_size(const std::string& value, const std::string& option) {
    if (value.empty() || value.front() == '-') {
        throw std::runtime_error("invalid value for " + option + ": " + value);
    }
    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::strtoull(value.c_str(), &end, 10);
    if (end == value.c_str() || *end != '\0' || errno == ERANGE ||
        parsed > static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) {
        throw std::runtime_error("invalid value for " + option + ": " + value);
    }
    return static_cast<std::size_t>(parsed);
}

pid_t parse_pid(const std::string& value) {
    char* end = nullptr;
    const long parsed = std::strtol(value.c_str(), &end, 10);
    if (end == value.c_str() || *end != '\0' || parsed <= 0) {
        throw std::runtime_error("invalid value for --pid: " + value);
    }
    return static_cast<pid_t>(parsed);
}

int parse_errno_token(const std::string& value) {
    static const std::unordered_map<std::string, int> names = {
        {"EPERM", EPERM},
        {"ENOENT", ENOENT},
        {"ESRCH", ESRCH},
        {"EINTR", EINTR},
        {"EIO", EIO},
        {"ENXIO", ENXIO},
        {"E2BIG", E2BIG},
        {"ENOEXEC", ENOEXEC},
        {"EBADF", EBADF},
        {"ECHILD", ECHILD},
        {"EAGAIN", EAGAIN},
        {"ENOMEM", ENOMEM},
        {"EACCES", EACCES},
        {"EFAULT", EFAULT},
        {"EBUSY", EBUSY},
        {"EEXIST", EEXIST},
        {"EXDEV", EXDEV},
        {"ENODEV", ENODEV},
        {"ENOTDIR", ENOTDIR},
        {"EISDIR", EISDIR},
        {"EINVAL", EINVAL},
        {"ENFILE", ENFILE},
        {"EMFILE", EMFILE},
        {"ENOTTY", ENOTTY},
        {"EFBIG", EFBIG},
        {"ENOSPC", ENOSPC},
        {"ESPIPE", ESPIPE},
        {"EROFS", EROFS},
        {"EMLINK", EMLINK},
        {"EPIPE", EPIPE},
        {"ENOSYS", ENOSYS},
        {"ETIMEDOUT", ETIMEDOUT},
        {"ECONNREFUSED", ECONNREFUSED},
        {"ECONNRESET", ECONNRESET},
        {"ENOTCONN", ENOTCONN},
        {"EADDRINUSE", EADDRINUSE},
        {"EADDRNOTAVAIL", EADDRNOTAVAIL},
    };
    const auto it = names.find(value);
    if (it != names.end()) {
        return it->second;
    }
    char* end = nullptr;
    const long parsed = std::strtol(value.c_str(), &end, 10);
    if (end != value.c_str() && *end == '\0' && parsed > 0 && parsed <= 4095) {
        return static_cast<int>(parsed);
    }
    throw std::runtime_error("unknown errno in --inject: " + value);
}

mini_strace::InjectionRule parse_injection(const std::string& spec) {
    const auto colon = spec.find(':');
    if (colon == std::string::npos || colon == 0) {
        throw std::runtime_error("invalid --inject spec: " + spec);
    }

    mini_strace::InjectionRule rule;
    rule.syscall = spec.substr(0, colon);
    if (!mini_strace::syscall_number_by_name(rule.syscall, rule.syscall_nr)) {
        throw std::runtime_error("unknown syscall in --inject: " + rule.syscall);
    }

    std::size_t offset = colon + 1;
    bool saw_error = false;
    while (offset <= spec.size()) {
        const auto next = spec.find(':', offset);
        const std::string token =
            spec.substr(offset, next == std::string::npos ? std::string::npos : next - offset);
        if (token.rfind("error=", 0) == 0) {
            rule.errno_value = parse_errno_token(token.substr(6));
            saw_error = true;
        } else if (token.rfind("when=", 0) == 0) {
            rule.when = parse_size(token.substr(5), "--inject when");
            if (rule.when == 0) {
                throw std::runtime_error("--inject when must be greater than zero");
            }
        } else if (!token.empty()) {
            throw std::runtime_error("unsupported --inject token: " + token);
        }
        if (next == std::string::npos) {
            break;
        }
        offset = next + 1;
    }

    if (!saw_error) {
        throw std::runtime_error("--inject currently requires error=ERRNO");
    }
    return rule;
}

}  // namespace

int main(int argc, char** argv) {
    mini_strace::TraceOptions options;
    std::string output_path;
    bool output_to_stdout = false;

    try {
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--help" || arg == "-h") {
                print_help(std::cout);
                return 0;
            }
            if (arg == "--") {
                for (++i; i < argc; ++i) {
                    options.command.emplace_back(argv[i]);
                }
                break;
            }
            if (arg == "--pid") {
                if (++i >= argc) {
                    throw std::runtime_error("--pid requires a value");
                }
                options.mode = mini_strace::TraceMode::Attach;
                options.attach_pid = parse_pid(argv[i]);
                continue;
            }
            if (arg == "--filter") {
                if (++i >= argc) {
                    throw std::runtime_error("--filter requires a value");
                }
                for (const auto& name : split_commas(argv[i])) {
                    std::uint64_t nr = 0;
                    if (!mini_strace::syscall_number_by_name(name, nr)) {
                        throw std::runtime_error("unknown syscall in --filter: " + name);
                    }
                    options.filters.insert(name);
                }
                continue;
            }
            if (arg == "--summary") {
                options.summary = true;
                continue;
            }
            if (arg == "--diagnose") {
                options.diagnose = true;
                continue;
            }
            if (arg == "--io-latency") {
                options.io_latency = true;
                continue;
            }
            if (arg == "--slow-us") {
                if (++i >= argc) {
                    throw std::runtime_error("--slow-us requires a value");
                }
                options.slow_io_threshold_us = parse_size(argv[i], "--slow-us");
                options.io_latency = true;
                continue;
            }
            if (arg == "--net") {
                options.net = true;
                continue;
            }
            if (arg == "--explain-deny") {
                options.explain_deny = true;
                continue;
            }
            if (arg == "--process") {
                options.process = true;
                continue;
            }
            if (arg == "--json") {
                options.json = true;
                continue;
            }
            if (arg == "--raw") {
                options.raw = true;
                continue;
            }
            if (arg == "--state") {
                options.show_state = true;
                continue;
            }
            if (arg == "--signals") {
                options.signals = true;
                continue;
            }
            if (arg == "--lifecycle") {
                options.lifecycle = true;
                continue;
            }
            if (arg == "--follow-fork" || arg == "-f") {
                options.follow_fork = true;
                continue;
            }
            if (arg == "--seccomp-bpf") {
                options.seccomp_bpf = true;
                continue;
            }
            if (arg == "--dump-seccomp" || arg == "--seccomp-dump") {
                options.dump_seccomp = true;
                continue;
            }
            if (arg == "--inject") {
                if (++i >= argc) {
                    throw std::runtime_error("--inject requires a value");
                }
                options.injections.push_back(parse_injection(argv[i]));
                continue;
            }
            if (arg == "--strings") {
                if (++i >= argc) {
                    throw std::runtime_error("--strings requires a value");
                }
                options.string_limit = parse_size(argv[i], "--strings");
                continue;
            }
            if (arg == "--max-events") {
                if (++i >= argc) {
                    throw std::runtime_error("--max-events requires a value");
                }
                options.max_events = parse_size(argv[i], "--max-events");
                continue;
            }
            if (arg == "--output") {
                if (++i >= argc) {
                    throw std::runtime_error("--output requires a value");
                }
                output_path = argv[i];
                output_to_stdout = output_path == "-";
                continue;
            }
            if (!arg.empty() && arg[0] == '-') {
                throw std::runtime_error("unknown option: " + arg);
            }
            for (; i < argc; ++i) {
                options.command.emplace_back(argv[i]);
            }
            break;
        }

        if (options.mode == mini_strace::TraceMode::Launch && options.command.empty()) {
            throw std::runtime_error("missing command; use --help for usage");
        }
        if (options.seccomp_bpf && options.mode != mini_strace::TraceMode::Launch) {
            throw std::runtime_error(
                "--seccomp-bpf is currently supported only with launched commands");
        }
        if (options.seccomp_bpf && options.filters.empty()) {
            throw std::runtime_error("--seccomp-bpf requires --filter");
        }

        std::ofstream file_out;
        std::ostream* out = &std::cerr;
        if (output_to_stdout) {
            out = &std::cout;
        } else if (!output_path.empty()) {
            file_out.open(output_path);
            if (!file_out) {
                throw std::runtime_error("failed to open output file: " + output_path);
            }
            out = &file_out;
        }

        const auto result = mini_strace::run_trace(options, *out, std::cerr);
        return result.exit_code;
    } catch (const std::exception& ex) {
        std::cerr << "mini-strace: " << ex.what() << '\n';
        return 1;
    }
}
