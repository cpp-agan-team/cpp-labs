#include "mem_map_viewer.hpp"

#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

struct CliOptions {
    int pid = -1;
    bool json = false;
    bool summary = false;
    bool snapshot = false;
    bool events = false;
    bool watch = false;
    bool proc_compat = false;
    bool with_smaps = false;
    bool probe_memory = false;
    bool residency = false;
    bool perf_sample = false;
    bool uffd_demo = false;
    bool insights = false;
    bool psi = false;
    bool oom_risk = false;
    bool pages = false;
    bool numa = false;
    bool page_flags = false;
    bool clear_soft_dirty = false;
    bool limits = false;
    bool reconcile = false;
    bool has_range = false;
    int growth_samples = 0;
    int interval_ms = 1000;
    int duration_ms = 1000;
    uint64_t uffd_length = 16 * 1024 * 1024;
    uint64_t range_begin = 0;
    uint64_t range_length = 0;
    std::string perf_event = "dtlb-miss";
    std::string uffd_mode = "missing";
    std::string cgroup_path;
    std::vector<std::string> trace_command;
    std::vector<std::string> diff_files;
};

void print_usage(std::ostream& out) {
    out << "mem-map-viewer --pid <pid> [--proc-compat] [--snapshot] [--summary] [--json]\n"
        << "mem-map-viewer --pid <pid> --residency [--with-smaps] [--json]\n"
        << "mem-map-viewer --pid <pid> --perf-sample [--perf-event "
           "dtlb-miss|cache-miss|cpu-clock]\n"
        << "mem-map-viewer --pid <pid> --pages --range <addr+len|addr-end> [--json]\n"
        << "mem-map-viewer --pid <pid> --numa --range <addr+len|addr-end> [--json]\n"
        << "mem-map-viewer --pid <pid> --page-flags --range <addr+len|addr-end> [--json]\n"
        << "mem-map-viewer --pid <pid> --clear-soft-dirty [--json]\n"
        << "mem-map-viewer --pid <pid> --limits [--json]\n"
        << "mem-map-viewer --pid <pid> --reconcile [--json]\n"
        << "mem-map-viewer --pid <pid> --growth-check <samples> [--interval-ms ms]\n"
        << "mem-map-viewer --pid <pid> --insights [--residency] [--perf-sample] [--cgroup self]\n"
        << "mem-map-viewer --uffd-demo [--uffd-mode missing|wp] [--json]\n"
        << "mem-map-viewer [--events|--snapshot] [--json] --trace [--] <program> [args...]\n"
        << "mem-map-viewer --cgroup <path> [--psi] [--oom-risk] [--json]\n"
        << "mem-map-viewer --diff <before.json> <after.json> [--json]\n";
}

int parse_positive_int(const char* text, const std::string& name) {
    char* end = nullptr;
    errno = 0;
    long value = std::strtol(text, &end, 10);
    if (!text[0] || (end && *end != '\0') || errno == ERANGE || value <= 0 || value > INT_MAX) {
        throw std::invalid_argument("invalid value for " + name);
    }
    return static_cast<int>(value);
}

uint64_t parse_positive_u64(const char* text, const std::string& name) {
    char* end = nullptr;
    errno = 0;
    unsigned long long value = std::strtoull(text, &end, 10);
    if (!text[0] || text[0] == '-' || (end && *end != '\0') || errno == ERANGE || value == 0) {
        throw std::invalid_argument("invalid value for " + name);
    }
    return static_cast<uint64_t>(value);
}

uint64_t parse_u64_token(const std::string& text, const std::string& name) {
    if (text.empty() || text[0] == '-') {
        throw std::invalid_argument("invalid value for " + name);
    }
    char suffix = '\0';
    std::string number = text;
    char last = text.back();
    if (last == 'k' || last == 'K' || last == 'm' || last == 'M' || last == 'g' || last == 'G') {
        suffix = last;
        number.pop_back();
    }
    if (number.empty()) {
        throw std::invalid_argument("invalid value for " + name);
    }
    char* end = nullptr;
    errno = 0;
    unsigned long long value = std::strtoull(number.c_str(), &end, 0);
    if (!number[0] || (end && *end != '\0') || errno == ERANGE) {
        throw std::invalid_argument("invalid value for " + name);
    }
    uint64_t multiplier = 1;
    if (suffix == 'k' || suffix == 'K') {
        multiplier = 1024;
    } else if (suffix == 'm' || suffix == 'M') {
        multiplier = 1024ULL * 1024ULL;
    } else if (suffix == 'g' || suffix == 'G') {
        multiplier = 1024ULL * 1024ULL * 1024ULL;
    }
    uint64_t parsed = static_cast<uint64_t>(value);
    if (parsed > std::numeric_limits<uint64_t>::max() / multiplier) {
        throw std::invalid_argument("invalid value for " + name);
    }
    return parsed * multiplier;
}

void parse_range_arg(const std::string& text, uint64_t* begin, uint64_t* length) {
    size_t plus = text.find('+');
    if (plus != std::string::npos) {
        *begin = parse_u64_token(text.substr(0, plus), "--range");
        *length = parse_u64_token(text.substr(plus + 1), "--range");
        if (*length == 0) {
            throw std::invalid_argument("invalid value for --range");
        }
        return;
    }

    size_t dash = text.find('-');
    if (dash == std::string::npos) {
        throw std::invalid_argument("invalid value for --range");
    }
    *begin = parse_u64_token(text.substr(0, dash), "--range");
    uint64_t end = parse_u64_token(text.substr(dash + 1), "--range");
    if (end <= *begin) {
        throw std::invalid_argument("invalid value for --range");
    }
    *length = end - *begin;
}

CliOptions parse_args(int argc, char** argv) {
    CliOptions options;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--pid" && i + 1 < argc) {
            options.pid = parse_positive_int(argv[++i], "--pid");
        } else if (arg == "--trace" && i + 1 < argc) {
            ++i;
            const bool explicit_separator = std::string(argv[i]) == "--";
            if (explicit_separator) {
                ++i;
            }
            while (i < argc) {
                std::string item = argv[i];
                if (!explicit_separator && item.rfind("--", 0) == 0) {
                    --i;
                    break;
                }
                options.trace_command.push_back(item);
                ++i;
            }
        } else if (arg == "--diff" && i + 2 < argc) {
            options.diff_files.push_back(argv[++i]);
            options.diff_files.push_back(argv[++i]);
        } else if (arg == "--json") {
            options.json = true;
        } else if (arg == "--summary") {
            options.summary = true;
        } else if (arg == "--snapshot") {
            options.snapshot = true;
        } else if (arg == "--events") {
            options.events = true;
        } else if (arg == "--watch") {
            options.watch = true;
        } else if (arg == "--proc-compat") {
            options.proc_compat = true;
        } else if (arg == "--with-smaps") {
            options.with_smaps = true;
        } else if (arg == "--probe-memory") {
            options.probe_memory = true;
        } else if (arg == "--residency") {
            options.residency = true;
        } else if (arg == "--perf-sample") {
            options.perf_sample = true;
        } else if (arg == "--uffd-demo") {
            options.uffd_demo = true;
        } else if (arg == "--insights") {
            options.insights = true;
        } else if (arg == "--growth-check" && i + 1 < argc) {
            options.growth_samples = parse_positive_int(argv[++i], "--growth-check");
        } else if (arg == "--perf-event" && i + 1 < argc) {
            options.perf_event = argv[++i];
        } else if (arg == "--duration-ms" && i + 1 < argc) {
            options.duration_ms = parse_positive_int(argv[++i], "--duration-ms");
        } else if (arg == "--uffd-mode" && i + 1 < argc) {
            options.uffd_mode = argv[++i];
        } else if (arg == "--uffd-length" && i + 1 < argc) {
            options.uffd_length = parse_positive_u64(argv[++i], "--uffd-length");
        } else if (arg == "--cgroup" && i + 1 < argc) {
            options.cgroup_path = argv[++i];
        } else if (arg == "--psi") {
            options.psi = true;
        } else if (arg == "--oom-risk") {
            options.oom_risk = true;
        } else if (arg == "--pages") {
            options.pages = true;
        } else if (arg == "--numa") {
            options.numa = true;
        } else if (arg == "--page-flags") {
            options.page_flags = true;
        } else if (arg == "--clear-soft-dirty") {
            options.clear_soft_dirty = true;
        } else if (arg == "--limits") {
            options.limits = true;
        } else if (arg == "--reconcile") {
            options.reconcile = true;
        } else if (arg == "--range" && i + 1 < argc) {
            parse_range_arg(argv[++i], &options.range_begin, &options.range_length);
            options.has_range = true;
        } else if (arg == "--interval-ms" && i + 1 < argc) {
            options.interval_ms = parse_positive_int(argv[++i], "--interval-ms");
        } else if (arg == "--help" || arg == "-h") {
            print_usage(std::cout);
            std::exit(0);
        } else {
            throw std::invalid_argument("unknown or incomplete argument: " + arg);
        }
    }

    const bool cgroup_secondary =
        options.insights && options.pid > 0 && !options.cgroup_path.empty();
    int modes = (options.pid > 0 ? 1 : 0) + (!options.trace_command.empty() ? 1 : 0) +
                (!options.diff_files.empty() ? 1 : 0) +
                (!options.cgroup_path.empty() && !cgroup_secondary ? 1 : 0) +
                (options.uffd_demo ? 1 : 0);
    if (modes != 1) {
        throw std::invalid_argument(
            "choose exactly one of --pid, --trace, --cgroup, --uffd-demo, or --diff");
    }
    if (options.events && options.snapshot) {
        throw std::invalid_argument("--events and --snapshot are mutually exclusive");
    }
    if ((options.psi || options.oom_risk) && options.cgroup_path.empty()) {
        throw std::invalid_argument("--psi and --oom-risk require --cgroup");
    }
    if (options.insights && options.trace_command.empty() && options.diff_files.empty() &&
        !options.uffd_demo && options.pid <= 0 && options.cgroup_path.empty()) {
        throw std::invalid_argument("--insights requires --pid or --cgroup");
    }
    if (options.insights &&
        (!options.trace_command.empty() || !options.diff_files.empty() || options.uffd_demo)) {
        throw std::invalid_argument("--insights is only valid with --pid and/or --cgroup");
    }
    if (options.residency && options.pid <= 0) {
        throw std::invalid_argument("--residency requires --pid");
    }
    if (options.perf_sample && options.pid <= 0) {
        throw std::invalid_argument("--perf-sample requires --pid");
    }
    if (options.pages && options.pid <= 0) {
        throw std::invalid_argument("--pages requires --pid");
    }
    if (options.numa && options.pid <= 0) {
        throw std::invalid_argument("--numa requires --pid");
    }
    if (options.page_flags && options.pid <= 0) {
        throw std::invalid_argument("--page-flags requires --pid");
    }
    if (options.clear_soft_dirty && options.pid <= 0) {
        throw std::invalid_argument("--clear-soft-dirty requires --pid");
    }
    if (options.limits && options.pid <= 0) {
        throw std::invalid_argument("--limits requires --pid");
    }
    if (options.reconcile && options.pid <= 0) {
        throw std::invalid_argument("--reconcile requires --pid");
    }
    const int page_modes =
        (options.pages ? 1 : 0) + (options.numa ? 1 : 0) + (options.page_flags ? 1 : 0);
    if (page_modes > 1) {
        throw std::invalid_argument("--pages, --numa, and --page-flags are mutually exclusive");
    }
    if (page_modes > 0 && !options.has_range) {
        throw std::invalid_argument("--pages, --numa, and --page-flags require --range");
    }
    if (options.has_range && page_modes == 0) {
        throw std::invalid_argument("--range is only valid with --pages, --numa, or --page-flags");
    }
    if (options.clear_soft_dirty && page_modes > 0) {
        throw std::invalid_argument("--clear-soft-dirty cannot be combined with page range modes");
    }
    if (options.limits && (page_modes > 0 || options.clear_soft_dirty || options.reconcile)) {
        throw std::invalid_argument(
            "--limits cannot be combined with page mutation/query or reconcile modes");
    }
    if (options.reconcile && (page_modes > 0 || options.clear_soft_dirty)) {
        throw std::invalid_argument(
            "--reconcile cannot be combined with page mutation/query modes");
    }
    if (options.reconcile && (options.residency || options.perf_sample || options.insights ||
                              options.growth_samples > 0)) {
        throw std::invalid_argument(
            "--reconcile cannot be combined with residency, perf, insights, or growth-check");
    }
    if (options.growth_samples > 0 && options.pid <= 0) {
        throw std::invalid_argument("--growth-check requires --pid");
    }
    if (options.growth_samples == 1) {
        throw std::invalid_argument("--growth-check requires at least 2 samples");
    }
    if (options.perf_event != "dtlb-miss" && options.perf_event != "cache-miss" &&
        options.perf_event != "cpu-clock") {
        throw std::invalid_argument("--perf-event must be dtlb-miss, cache-miss, or cpu-clock");
    }
    if (options.uffd_mode != "missing" && options.uffd_mode != "wp") {
        throw std::invalid_argument("--uffd-mode must be missing or wp");
    }
    if (options.interval_ms <= 0) {
        throw std::invalid_argument("--interval-ms must be positive");
    }
    return options;
}

mmv::SnapshotOptions snapshot_options(const CliOptions& cli) {
    mmv::SnapshotOptions options;
    options.with_smaps = cli.with_smaps || cli.insights || cli.growth_samples > 0;
    options.probe_memory = cli.probe_memory;
    return options;
}

void print_snapshot(const CliOptions& cli, const mmv::Snapshot& snapshot) {
    if (cli.json) {
        mmv::print_snapshot_json(std::cout, snapshot);
    } else {
        mmv::print_snapshot_table(std::cout, snapshot, cli.summary);
    }
}

mmv::Snapshot read_snapshot_file(const std::string& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("cannot open snapshot: " + path);
    }
    return mmv::parse_snapshot_json(input);
}

}  // namespace

int main(int argc, char** argv) {
    try {
        CliOptions cli = parse_args(argc, argv);
        if (!cli.diff_files.empty()) {
            auto diff = mmv::diff_snapshots(read_snapshot_file(cli.diff_files[0]),
                                            read_snapshot_file(cli.diff_files[1]));
            if (cli.json) {
                mmv::print_diff_json(std::cout, diff);
            } else {
                mmv::print_diff_table(std::cout, diff);
            }
            return 0;
        }

        if (cli.uffd_demo) {
            mmv::UffdDemoResult result = mmv::run_uffd_demo(cli.uffd_mode, cli.uffd_length);
            if (cli.json) {
                mmv::print_uffd_json(std::cout, result);
            } else {
                mmv::print_uffd_table(std::cout, result);
            }
            return 0;
        }

        if (!cli.cgroup_path.empty() && !(cli.insights && cli.pid > 0)) {
            do {
                mmv::CgroupMemoryHealth health = mmv::read_cgroup_memory_health(cli.cgroup_path);
                if (cli.insights) {
                    std::vector<mmv::Insight> insights =
                        mmv::generate_insights(nullptr, nullptr, nullptr, &health);
                    if (cli.json) {
                        mmv::print_insights_json(std::cout, insights);
                    } else {
                        mmv::print_insights_table(std::cout, insights);
                    }
                } else if (cli.json) {
                    mmv::print_cgroup_json(std::cout, health);
                } else {
                    mmv::print_cgroup_table(std::cout, health, cli.psi, cli.oom_risk);
                }
                if (cli.watch) {
                    std::cout << std::flush;
                    std::this_thread::sleep_for(std::chrono::milliseconds(cli.interval_ms));
                }
            } while (cli.watch);
            return 0;
        }

        if (!cli.trace_command.empty()) {
            mmv::TraceResult result = mmv::trace_program(cli.trace_command, snapshot_options(cli));
            if (cli.events && !cli.snapshot) {
                if (cli.json) {
                    mmv::print_events_json(std::cout, result.events);
                } else {
                    mmv::print_events_table(std::cout, result.events);
                }
            } else {
                print_snapshot(cli, result.snapshot);
            }
            return result.exit_status;
        }

        if (cli.pages) {
            mmv::PageMapReport report =
                mmv::sample_pagemap(cli.pid, cli.range_begin, cli.range_length);
            if (cli.json) {
                mmv::print_pagemap_json(std::cout, report);
            } else {
                mmv::print_pagemap_table(std::cout, report);
            }
            return 0;
        }

        if (cli.numa) {
            mmv::NumaReport report = mmv::sample_numa(cli.pid, cli.range_begin, cli.range_length);
            if (cli.json) {
                mmv::print_numa_json(std::cout, report);
            } else {
                mmv::print_numa_table(std::cout, report);
            }
            return 0;
        }

        if (cli.page_flags) {
            mmv::PageFlagsReport report =
                mmv::sample_page_flags(cli.pid, cli.range_begin, cli.range_length);
            if (cli.json) {
                mmv::print_page_flags_json(std::cout, report);
            } else {
                mmv::print_page_flags_table(std::cout, report);
            }
            return 0;
        }

        if (cli.clear_soft_dirty) {
            mmv::ClearRefsReport report = mmv::clear_soft_dirty(cli.pid);
            if (cli.json) {
                mmv::print_clear_refs_json(std::cout, report);
            } else {
                mmv::print_clear_refs_table(std::cout, report);
            }
            return report.available ? 0 : 1;
        }

        if (cli.limits && !cli.insights) {
            mmv::ResourceLimitsReport report = mmv::read_resource_limits(cli.pid);
            if (cli.json) {
                mmv::print_resource_limits_json(std::cout, report);
            } else {
                mmv::print_resource_limits_table(std::cout, report);
            }
            return report.available ? 0 : 1;
        }

        do {
            mmv::Snapshot snapshot = mmv::read_proc_snapshot(cli.pid, snapshot_options(cli));
            if (cli.growth_samples > 0) {
                mmv::GrowthReport report = mmv::check_growth(
                    cli.pid, cli.growth_samples, cli.interval_ms, snapshot_options(cli));
                if (cli.json) {
                    mmv::print_growth_json(std::cout, report);
                } else {
                    mmv::print_growth_table(std::cout, report);
                }
                return 0;
            } else if (cli.insights) {
                mmv::ResidencyReport residency = mmv::sample_residency(snapshot);
                std::optional<mmv::PerfSampleReport> perf;
                std::optional<mmv::CgroupMemoryHealth> cgroup;
                std::optional<mmv::ResourceLimitsReport> limits;
                if (cli.perf_sample) {
                    perf = mmv::sample_perf_event(snapshot, cli.perf_event, cli.duration_ms);
                }
                if (!cli.cgroup_path.empty()) {
                    cgroup = mmv::read_cgroup_memory_health(cli.cgroup_path);
                }
                if (cli.limits) {
                    limits = mmv::read_resource_limits(cli.pid);
                }
                std::vector<mmv::Insight> insights = mmv::generate_insights(
                    &snapshot, &residency, perf ? &*perf : nullptr, cgroup ? &*cgroup : nullptr,
                    limits ? &*limits : nullptr);
                if (cli.json) {
                    mmv::print_insights_json(std::cout, insights);
                } else {
                    mmv::print_insights_table(std::cout, insights);
                }
            } else if (cli.reconcile) {
                mmv::ReconcileReport report =
                    mmv::reconcile_with_proc_maps(snapshot, snapshot_options(cli));
                if (cli.json) {
                    mmv::print_reconcile_json(std::cout, report);
                } else {
                    mmv::print_reconcile_table(std::cout, report);
                }
            } else if (cli.perf_sample) {
                mmv::PerfSampleReport report =
                    mmv::sample_perf_event(snapshot, cli.perf_event, cli.duration_ms);
                if (cli.json) {
                    mmv::print_perf_json(std::cout, report);
                } else {
                    mmv::print_perf_table(std::cout, report);
                }
            } else if (cli.residency) {
                mmv::ResidencyReport report = mmv::sample_residency(snapshot);
                if (cli.json) {
                    mmv::print_residency_json(std::cout, report);
                } else {
                    mmv::print_residency_table(std::cout, report);
                }
            } else {
                print_snapshot(cli, snapshot);
            }
            if (cli.watch) {
                std::cout << std::flush;
                std::this_thread::sleep_for(std::chrono::milliseconds(cli.interval_ms));
            }
        } while (cli.watch);
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "mem-map-viewer: " << ex.what() << '\n';
        print_usage(std::cerr);
        return 1;
    }
}
