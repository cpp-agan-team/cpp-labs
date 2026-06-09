#include "fd_inspector.hpp"

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <limits>
#include <string>
#include <thread>

namespace {

struct CliOptions {
    int pid = -1;
    int max_fd = 65536;
    bool json = false;
    bool only_socket = false;
    bool watch = false;
    bool proc_fallback = false;
    bool io_uring = false;
    bool interval_set = false;
    int leak_seconds = 0;
    int interval_ms = 1000;
};

void print_usage(std::ostream& out) {
    out << "fd-inspector --pid <pid> [--json] [--socket] [--max-fd <n|0=auto>] [--proc-fallback] "
           "[--io-uring]\n"
        << "fd-inspector --pid <pid> --watch [--interval-ms <n>]\n"
        << "fd-inspector --pid <pid> --leak-check <seconds> [--json]\n";
}

int parse_int_arg(const char* value, const std::string& name) {
    char* end = nullptr;
    errno = 0;
    long parsed = std::strtol(value, &end, 10);
    if (!value[0] || (end && *end != '\0') || errno == ERANGE || parsed < 0 ||
        parsed > std::numeric_limits<int>::max()) {
        throw std::invalid_argument("invalid value for " + name);
    }
    return static_cast<int>(parsed);
}

CliOptions parse_args(int argc, char** argv) {
    CliOptions options;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--pid" && i + 1 < argc) {
            options.pid = parse_int_arg(argv[++i], "--pid");
        } else if (arg == "--json") {
            options.json = true;
        } else if (arg == "--socket") {
            options.only_socket = true;
        } else if (arg == "--watch") {
            options.watch = true;
        } else if (arg == "--proc-fallback") {
            options.proc_fallback = true;
        } else if (arg == "--io-uring") {
            options.io_uring = true;
        } else if (arg == "--leak-check" && i + 1 < argc) {
            options.leak_seconds = parse_int_arg(argv[++i], "--leak-check");
        } else if (arg == "--max-fd" && i + 1 < argc) {
            options.max_fd = parse_int_arg(argv[++i], "--max-fd");
        } else if (arg == "--interval-ms" && i + 1 < argc) {
            options.interval_ms = parse_int_arg(argv[++i], "--interval-ms");
            options.interval_set = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage(std::cout);
            std::exit(0);
        } else {
            throw std::invalid_argument("unknown or incomplete argument: " + arg);
        }
    }

    if (options.pid <= 0) {
        throw std::invalid_argument("--pid is required");
    }
    if (options.watch && options.leak_seconds > 0) {
        throw std::invalid_argument("--watch and --leak-check are mutually exclusive");
    }
    if (options.interval_set && !options.watch) {
        throw std::invalid_argument("--interval-ms is only valid with --watch");
    }
    // --max-fd 0 asks the library to derive the limit from RLIMIT_NOFILE.
    if (options.interval_ms <= 0) {
        throw std::invalid_argument("--interval-ms must be positive");
    }
    return options;
}

void run_once(const CliOptions& cli, const fdi::InspectOptions& inspect_options) {
    auto entries = fdi::inspect_pid(cli.pid, inspect_options);
    if (cli.json) {
        fdi::print_json(std::cout, entries, cli.only_socket);
    } else {
        fdi::print_table(std::cout, entries, cli.only_socket);
    }
}

void run_watch(const CliOptions& cli, const fdi::InspectOptions& inspect_options) {
    while (true) {
        run_once(cli, inspect_options);
        std::cout << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(cli.interval_ms));
    }
}

}  // namespace

int main(int argc, char** argv) {
    try {
        CliOptions cli = parse_args(argc, argv);
        fdi::InspectOptions inspect_options;
        inspect_options.max_fd = cli.max_fd;
        inspect_options.force_proc_fallback = cli.proc_fallback;
        inspect_options.use_io_uring = cli.io_uring;

        if (cli.leak_seconds > 0) {
            fdi::LeakReport report = fdi::check_leak(cli.pid, cli.leak_seconds, inspect_options);
            fdi::print_leak_report(std::cout, report, cli.json);
            return report.suspected ? 2 : 0;
        }

        if (cli.watch) {
            run_watch(cli, inspect_options);
            return 0;
        }

        run_once(cli, inspect_options);
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "fd-inspector: " << ex.what() << '\n';
        print_usage(std::cerr);
        return 1;
    }
}
