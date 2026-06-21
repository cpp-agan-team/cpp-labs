#pragma once

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

namespace mmv {

enum class RegionKind {
    Text,
    Data,
    Heap,
    Stack,
    ThreadStack,
    SharedLibrary,
    FileMapping,
    Anonymous,
    Vdso,
    Vvar,
    Vsyscall,
    Unknown,
};

enum class MapEventType {
    Mmap,
    Munmap,
    Mprotect,
    Brk,
    Mremap,
    Exec,
    ProcSeed,
};

struct Perms {
    bool read = false;
    bool write = false;
    bool exec = false;
    bool shared = false;
};

struct MappingSource {
    int fd = -1;
    uint64_t inode = 0;
    uint64_t device = 0;
    uint64_t offset = 0;
    std::string path;
    bool deleted = false;
};

struct RegionProbe {
    bool attempted = false;
    bool readable = false;
    bool has_elf_header = false;
    size_t bytes_read = 0;
};

struct Region {
    uint64_t begin = 0;
    uint64_t end = 0;
    Perms perms;
    RegionKind kind = RegionKind::Unknown;
    MappingSource source;
    uint64_t rss_kb = 0;
    uint64_t pss_kb = 0;
    uint64_t private_dirty_kb = 0;
    std::string label;
    std::string provenance = "unknown";
    RegionProbe probe;
};

struct MapEvent {
    MapEventType type = MapEventType::ProcSeed;
    uint64_t timestamp_ns = 0;
    int pid = -1;
    int tid = -1;
    uint64_t address = 0;
    uint64_t length = 0;
    uint64_t new_address = 0;
    uint64_t new_length = 0;
    Perms perms;
    uint64_t flags = 0;
    int fd = -1;
    uint64_t offset = 0;
    int64_t result = 0;
    MappingSource source;
    std::string syscall;
    bool success = false;
};

struct Snapshot {
    int pid = -1;
    uint64_t timestamp_ns = 0;
    std::vector<Region> regions;
};

struct SummaryEntry {
    std::string key;
    uint64_t size = 0;
    uint64_t rss_kb = 0;
    uint64_t pss_kb = 0;
    size_t count = 0;
};

struct DiffEntry {
    std::string key;
    int64_t size_delta = 0;
    int64_t rss_delta = 0;
    int64_t pss_delta = 0;
    int64_t count_delta = 0;
};

struct ResidencyEntry {
    uint64_t begin = 0;
    uint64_t end = 0;
    std::string key;
    uint64_t total_pages = 0;
    uint64_t resident_pages = 0;
    double resident_ratio = 0.0;
    bool exact = false;
    std::string note;
};

struct ResidencyReport {
    int pid = -1;
    uint64_t page_size = 0;
    bool exact = false;
    std::vector<ResidencyEntry> entries;
};

struct PsiLine {
    double avg10 = 0.0;
    double avg60 = 0.0;
    double avg300 = 0.0;
    uint64_t total = 0;
};

struct CgroupMemoryHealth {
    std::string path;
    uint64_t current_bytes = 0;
    uint64_t max_bytes = 0;
    bool has_limit = false;
    uint64_t anon_bytes = 0;
    uint64_t file_bytes = 0;
    uint64_t kernel_stack_bytes = 0;
    uint64_t oom_events = 0;
    uint64_t oom_kill_events = 0;
    bool has_pressure = false;
    PsiLine some;
    PsiLine full;
    double usage_ratio = 0.0;
    double oom_risk = 0.0;
};

struct PerfHotspot {
    std::string key;
    uint64_t samples = 0;
    uint64_t total_weight = 0;
    uint64_t hotspot_ip = 0;
    uint64_t hotspot_addr = 0;
};

struct PerfSampleReport {
    int pid = -1;
    std::string event;
    int duration_ms = 0;
    bool available = false;
    std::string error;
    int perf_event_paranoid = 0;
    uint64_t total_samples = 0;
    uint64_t lost_samples = 0;
    std::vector<PerfHotspot> hotspots;
};

struct UffdFaultEvent {
    uint64_t address = 0;
    uint64_t offset = 0;
    uint64_t timestamp_ns = 0;
    bool write = false;
    bool wp = false;
};

struct UffdDemoResult {
    bool available = false;
    std::string error;
    std::string mode;
    uint64_t page_size = 0;
    uint64_t base = 0;
    uint64_t length = 0;
    std::vector<UffdFaultEvent> events;
};

struct Insight {
    std::string type;
    std::string key;
    double score = 0.0;
    std::string evidence;
    std::string suggestion;
};

struct GrowthBucket {
    std::string key;
    int64_t size_delta = 0;
    int64_t rss_delta = 0;
    int64_t pss_delta = 0;
    int64_t count_delta = 0;
};

struct GrowthReport {
    int pid = -1;
    int samples = 0;
    int interval_ms = 0;
    bool monotonic_size = false;
    bool monotonic_rss = false;
    double size_slope_bytes_per_sample = 0.0;
    double rss_slope_kb_per_sample = 0.0;
    double size_r2 = 0.0;
    double rss_r2 = 0.0;
    uint64_t first_size = 0;
    uint64_t last_size = 0;
    uint64_t first_rss_kb = 0;
    uint64_t last_rss_kb = 0;
    std::vector<GrowthBucket> buckets;
};

struct PageMapReport {
    int pid = -1;
    bool available = false;
    std::string error;
    uint64_t page_size = 0;
    uint64_t range_begin = 0;
    uint64_t range_end = 0;
    uint64_t total_pages = 0;
    uint64_t present_pages = 0;
    uint64_t swapped_pages = 0;
    uint64_t soft_dirty_pages = 0;
    uint64_t file_or_shared_pages = 0;
    uint64_t exclusive_pages = 0;
    uint64_t pfn_visible_pages = 0;
    bool pfn_visible = false;
};

struct NumaNodeCount {
    int node = -1;
    uint64_t pages = 0;
};

struct NumaStatusCount {
    int status = 0;
    uint64_t pages = 0;
};

struct NumaReport {
    int pid = -1;
    bool available = false;
    std::string error;
    uint64_t page_size = 0;
    uint64_t range_begin = 0;
    uint64_t range_end = 0;
    uint64_t total_pages = 0;
    uint64_t located_pages = 0;
    std::vector<NumaNodeCount> nodes;
    std::vector<NumaStatusCount> statuses;
};

struct PageFlagCount {
    std::string name;
    uint64_t pages = 0;
};

struct PageFlagsReport {
    int pid = -1;
    bool available = false;
    std::string error;
    uint64_t page_size = 0;
    uint64_t range_begin = 0;
    uint64_t range_end = 0;
    uint64_t total_pages = 0;
    uint64_t present_pages = 0;
    uint64_t pfn_visible_pages = 0;
    bool pfn_visible = false;
    std::vector<PageFlagCount> flags;
};

struct ClearRefsReport {
    int pid = -1;
    bool available = false;
    std::string error;
    std::string mode;
};

struct ResourceLimitEntry {
    std::string name;
    uint64_t soft = 0;
    uint64_t hard = 0;
    bool soft_infinity = false;
    bool hard_infinity = false;
};

struct ResourceLimitsReport {
    int pid = -1;
    bool available = false;
    std::string error;
    std::vector<ResourceLimitEntry> limits;
};

struct ReconcileMismatch {
    std::string type;
    uint64_t begin = 0;
    uint64_t end = 0;
    std::string observed;
    std::string truth;
};

struct ReconcileReport {
    int pid = -1;
    std::string truth_source;
    size_t observed_regions = 0;
    size_t truth_regions = 0;
    size_t missing_regions = 0;
    size_t extra_regions = 0;
    size_t metadata_mismatches = 0;
    std::vector<ReconcileMismatch> mismatches;
};

struct TraceResult {
    int pid = -1;
    int exit_status = 0;
    std::vector<MapEvent> events;
    Snapshot snapshot;
};

struct SnapshotOptions {
    bool with_smaps = false;
    bool probe_memory = false;
};

Snapshot read_proc_snapshot(int pid, const SnapshotOptions& options);
TraceResult trace_program(const std::vector<std::string>& command, const SnapshotOptions& options);
std::vector<SummaryEntry> summarize_snapshot(const Snapshot& snapshot);
std::vector<DiffEntry> diff_snapshots(const Snapshot& before, const Snapshot& after);
ResidencyReport sample_residency(const Snapshot& snapshot);
CgroupMemoryHealth read_cgroup_memory_health(const std::string& path);
PerfSampleReport sample_perf_event(const Snapshot& snapshot, const std::string& event,
                                   int duration_ms);
UffdDemoResult run_uffd_demo(const std::string& mode, uint64_t length);
std::vector<Insight> generate_insights(const Snapshot* snapshot, const ResidencyReport* residency,
                                       const PerfSampleReport* perf,
                                       const CgroupMemoryHealth* cgroup,
                                       const ResourceLimitsReport* limits = nullptr);
GrowthReport check_growth(int pid, int samples, int interval_ms, const SnapshotOptions& options);
PageMapReport sample_pagemap(int pid, uint64_t begin, uint64_t length);
NumaReport sample_numa(int pid, uint64_t begin, uint64_t length);
PageFlagsReport sample_page_flags(int pid, uint64_t begin, uint64_t length);
ClearRefsReport clear_soft_dirty(int pid);
ResourceLimitsReport read_resource_limits(int pid);
ReconcileReport reconcile_with_proc_maps(const Snapshot& observed, const SnapshotOptions& options);

Snapshot parse_snapshot_json(std::istream& input);

void print_snapshot_table(std::ostream& out, const Snapshot& snapshot, bool summary);
void print_events_table(std::ostream& out, const std::vector<MapEvent>& events);
void print_diff_table(std::ostream& out, const std::vector<DiffEntry>& diff);
void print_residency_table(std::ostream& out, const ResidencyReport& report);
void print_cgroup_table(std::ostream& out, const CgroupMemoryHealth& health, bool show_psi,
                        bool show_risk);
void print_perf_table(std::ostream& out, const PerfSampleReport& report);
void print_uffd_table(std::ostream& out, const UffdDemoResult& result);
void print_insights_table(std::ostream& out, const std::vector<Insight>& insights);
void print_growth_table(std::ostream& out, const GrowthReport& report);
void print_pagemap_table(std::ostream& out, const PageMapReport& report);
void print_numa_table(std::ostream& out, const NumaReport& report);
void print_page_flags_table(std::ostream& out, const PageFlagsReport& report);
void print_clear_refs_table(std::ostream& out, const ClearRefsReport& report);
void print_resource_limits_table(std::ostream& out, const ResourceLimitsReport& report);
void print_reconcile_table(std::ostream& out, const ReconcileReport& report);
void print_snapshot_json(std::ostream& out, const Snapshot& snapshot);
void print_events_json(std::ostream& out, const std::vector<MapEvent>& events);
void print_diff_json(std::ostream& out, const std::vector<DiffEntry>& diff);
void print_residency_json(std::ostream& out, const ResidencyReport& report);
void print_cgroup_json(std::ostream& out, const CgroupMemoryHealth& health);
void print_perf_json(std::ostream& out, const PerfSampleReport& report);
void print_uffd_json(std::ostream& out, const UffdDemoResult& result);
void print_insights_json(std::ostream& out, const std::vector<Insight>& insights);
void print_growth_json(std::ostream& out, const GrowthReport& report);
void print_pagemap_json(std::ostream& out, const PageMapReport& report);
void print_numa_json(std::ostream& out, const NumaReport& report);
void print_page_flags_json(std::ostream& out, const PageFlagsReport& report);
void print_clear_refs_json(std::ostream& out, const ClearRefsReport& report);
void print_resource_limits_json(std::ostream& out, const ResourceLimitsReport& report);
void print_reconcile_json(std::ostream& out, const ReconcileReport& report);

const char* kind_name(RegionKind kind);
const char* event_type_name(MapEventType type);
std::string perms_string(const Perms& perms);

}  // namespace mmv
