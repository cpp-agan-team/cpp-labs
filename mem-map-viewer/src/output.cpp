#include "internal.hpp"

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace mmv {
namespace {

std::string json_escape(const std::string& input) {
    std::ostringstream out;
    for (char ch : input) {
        const auto c = static_cast<unsigned char>(ch);
        switch (c) {
            case '\\':
                out << "\\\\";
                break;
            case '"':
                out << "\\\"";
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
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(c) << std::dec << std::setfill(' ');
                } else {
                    out << static_cast<char>(c);
                }
                break;
        }
    }
    return out.str();
}

uint64_t abs_delta(int64_t value) {
    if (value >= 0) {
        return static_cast<uint64_t>(value);
    }
    return static_cast<uint64_t>(-(value + 1)) + 1;
}

void print_hex(std::ostream& out, uint64_t value) {
    out << "0x" << std::hex << value << std::dec;
}

void print_region_json(std::ostream& out, const Region& region) {
    out << "{";
    out << "\"begin\":\"0x" << std::hex << region.begin << std::dec << "\"";
    out << ",\"end\":\"0x" << std::hex << region.end << std::dec << "\"";
    out << ",\"size\":" << detail::region_size(region);
    out << ",\"kind\":\"" << kind_name(region.kind) << "\"";
    out << ",\"perms\":\"" << perms_string(region.perms) << "\"";
    out << ",\"rss_kb\":" << region.rss_kb;
    out << ",\"pss_kb\":" << region.pss_kb;
    out << ",\"private_dirty_kb\":" << region.private_dirty_kb;
    out << ",\"label\":\"" << json_escape(region.label) << "\"";
    out << ",\"provenance\":\"" << json_escape(region.provenance) << "\"";
    out << ",\"source\":{";
    out << "\"fd\":" << region.source.fd;
    out << ",\"inode\":" << region.source.inode;
    out << ",\"device\":" << region.source.device;
    out << ",\"offset\":" << region.source.offset;
    out << ",\"path\":\"" << json_escape(region.source.path) << "\"";
    out << ",\"deleted\":" << (region.source.deleted ? "true" : "false");
    out << "}";
    out << ",\"probe\":{";
    out << "\"attempted\":" << (region.probe.attempted ? "true" : "false");
    out << ",\"readable\":" << (region.probe.readable ? "true" : "false");
    out << ",\"has_elf_header\":" << (region.probe.has_elf_header ? "true" : "false");
    out << ",\"bytes_read\":" << region.probe.bytes_read;
    out << "}";
    out << "}";
}

void print_event_json_item(std::ostream& out, const MapEvent& event) {
    out << "{";
    out << "\"type\":\"" << event_type_name(event.type) << "\"";
    out << ",\"syscall\":\"" << json_escape(event.syscall) << "\"";
    out << ",\"pid\":" << event.pid;
    out << ",\"tid\":" << event.tid;
    out << ",\"timestamp_ns\":" << event.timestamp_ns;
    out << ",\"success\":" << (event.success ? "true" : "false");
    out << ",\"address\":\"0x" << std::hex << event.address << std::dec << "\"";
    out << ",\"length\":" << event.length;
    out << ",\"new_address\":\"0x" << std::hex << event.new_address << std::dec << "\"";
    out << ",\"new_length\":" << event.new_length;
    out << ",\"perms\":\"" << perms_string(event.perms) << "\"";
    out << ",\"fd\":" << event.fd;
    out << ",\"offset\":" << event.offset;
    out << ",\"result\":" << event.result;
    out << ",\"source_path\":\"" << json_escape(event.source.path) << "\"";
    out << "}";
}

}  // namespace

void print_snapshot_table(std::ostream& out, const Snapshot& snapshot, bool summary) {
    if (summary) {
        out << std::left << std::setw(44) << "KIND/SOURCE" << std::right << std::setw(12) << "SIZE"
            << std::setw(10) << "RSS" << std::setw(10) << "PSS" << std::setw(8) << "COUNT" << '\n';
        for (const SummaryEntry& entry : summarize_snapshot(snapshot)) {
            out << std::left << std::setw(44) << entry.key << std::right << std::setw(12)
                << detail::format_size(entry.size) << std::setw(10)
                << (entry.rss_kb == 0 ? "-" : detail::format_size(entry.rss_kb * 1024))
                << std::setw(10)
                << (entry.pss_kb == 0 ? "-" : detail::format_size(entry.pss_kb * 1024))
                << std::setw(8) << entry.count << '\n';
        }
        return;
    }

    out << std::left << std::setw(14) << "REGION" << std::setw(35) << "RANGE" << std::setw(9)
        << "SIZE" << std::setw(7) << "PERM" << std::setw(9) << "RSS" << std::setw(9) << "PSS"
        << "SOURCE\n";
    for (const Region& region : snapshot.regions) {
        std::ostringstream range;
        range << std::hex << region.begin << "-" << region.end << std::dec;
        std::string source = detail::source_key(region);
        if (region.probe.attempted) {
            source += region.probe.readable ? " readable" : " unreadable";
            if (region.probe.has_elf_header) {
                source += " elf";
            }
        }
        out << std::left << std::setw(14) << kind_name(region.kind) << std::setw(35) << range.str()
            << std::setw(9) << detail::format_size(detail::region_size(region)) << std::setw(7)
            << perms_string(region.perms) << std::setw(9)
            << (region.rss_kb == 0 ? "-" : detail::format_size(region.rss_kb * 1024))
            << std::setw(9)
            << (region.pss_kb == 0 ? "-" : detail::format_size(region.pss_kb * 1024)) << source
            << '\n';
    }
}

void print_events_table(std::ostream& out, const std::vector<MapEvent>& events) {
    out << std::left << std::setw(8) << "TID" << std::setw(11) << "EVENT" << std::setw(20) << "ADDR"
        << std::setw(12) << "SIZE" << std::setw(7) << "PERM"
        << "SOURCE\n";
    for (const MapEvent& event : events) {
        std::ostringstream addr;
        print_hex(addr, event.address);
        out << std::left << std::setw(8) << event.tid << std::setw(11)
            << event_type_name(event.type) << std::setw(20) << addr.str() << std::setw(12)
            << detail::format_size(event.length) << std::setw(7) << perms_string(event.perms)
            << (event.source.path.empty() ? event.syscall : event.source.path) << '\n';
    }
}

void print_diff_table(std::ostream& out, const std::vector<DiffEntry>& diff) {
    out << std::left << std::setw(44) << "KIND/SOURCE" << std::right << std::setw(14)
        << "SIZE_DELTA" << std::setw(12) << "RSS_DELTA" << std::setw(12) << "PSS_DELTA"
        << std::setw(8) << "COUNT" << '\n';
    for (const DiffEntry& entry : diff) {
        out << std::left << std::setw(44) << entry.key << std::right << std::setw(14)
            << (entry.size_delta >= 0 ? "+" : "")
            << detail::format_size(abs_delta(entry.size_delta)) << std::setw(12)
            << (entry.rss_delta >= 0 ? "+" : "")
            << detail::format_size(abs_delta(entry.rss_delta) * 1024) << std::setw(12)
            << (entry.pss_delta >= 0 ? "+" : "")
            << detail::format_size(abs_delta(entry.pss_delta) * 1024) << std::setw(8)
            << entry.count_delta << '\n';
    }
}

void print_residency_table(std::ostream& out, const ResidencyReport& report) {
    out << "Residency mode: " << (report.exact ? "mincore exact" : "smaps RSS approximation")
        << "  page_size=" << report.page_size << '\n';
    out << std::left << std::setw(44) << "KIND/SOURCE" << std::right << std::setw(12) << "SIZE"
        << std::setw(12) << "RESIDENT" << std::setw(10) << "RATIO" << std::setw(18) << "PAGES"
        << "  NOTE\n";
    for (const ResidencyEntry& entry : report.entries) {
        const uint64_t size = entry.end > entry.begin ? entry.end - entry.begin : 0;
        std::ostringstream ratio;
        ratio << std::fixed << std::setprecision(1) << (entry.resident_ratio * 100.0) << "%";
        std::ostringstream pages;
        pages << entry.resident_pages << "/" << entry.total_pages;
        out << std::left << std::setw(44) << entry.key << std::right << std::setw(12)
            << detail::format_size(size) << std::setw(12)
            << detail::format_size(entry.resident_pages * report.page_size) << std::setw(10)
            << ratio.str() << std::setw(18) << pages.str() << "  " << entry.note << '\n';
    }
}

void print_cgroup_table(std::ostream& out, const CgroupMemoryHealth& health, bool show_psi,
                        bool show_risk) {
    out << "Cgroup: " << health.path << '\n';
    out << "Memory: " << detail::format_size(health.current_bytes) << " / ";
    if (health.has_limit) {
        out << detail::format_size(health.max_bytes) << " (";
        out << std::fixed << std::setprecision(1) << (health.usage_ratio * 100.0) << "%)";
    } else {
        out << "max";
    }
    out << '\n';
    out << "anon=" << detail::format_size(health.anon_bytes)
        << " file=" << detail::format_size(health.file_bytes)
        << " kernel_stack=" << detail::format_size(health.kernel_stack_bytes) << '\n';
    out << "oom=" << health.oom_events << " oom_kill=" << health.oom_kill_events << '\n';
    if (show_psi && health.has_pressure) {
        out << "psi some avg10=" << health.some.avg10 << " avg60=" << health.some.avg60
            << " avg300=" << health.some.avg300 << " total=" << health.some.total << '\n';
        out << "psi full avg10=" << health.full.avg10 << " avg60=" << health.full.avg60
            << " avg300=" << health.full.avg300 << " total=" << health.full.total << '\n';
    }
    if (show_risk) {
        out << "oom_risk=" << std::fixed << std::setprecision(2) << health.oom_risk << '\n';
    }
}

void print_perf_table(std::ostream& out, const PerfSampleReport& report) {
    out << "Perf event: " << report.event << " pid=" << report.pid
        << " duration_ms=" << report.duration_ms << " paranoid=" << report.perf_event_paranoid
        << '\n';
    if (!report.available) {
        out << "unavailable: " << report.error << '\n';
        return;
    }
    out << "total_samples=" << report.total_samples << " lost_samples=" << report.lost_samples
        << '\n';
    out << std::left << std::setw(44) << "KIND/SOURCE" << std::right << std::setw(12) << "SAMPLES"
        << std::setw(12) << "AVG_WEIGHT" << std::setw(20) << "HOTSPOT_IP" << std::setw(20)
        << "HOTSPOT_ADDR" << '\n';
    for (const PerfHotspot& hotspot : report.hotspots) {
        const uint64_t avg_weight =
            hotspot.samples == 0 ? 0 : hotspot.total_weight / hotspot.samples;
        std::ostringstream ip;
        print_hex(ip, hotspot.hotspot_ip);
        std::ostringstream addr;
        print_hex(addr, hotspot.hotspot_addr);
        out << std::left << std::setw(44) << hotspot.key << std::right << std::setw(12)
            << hotspot.samples << std::setw(12) << avg_weight << std::setw(20) << ip.str()
            << std::setw(20) << addr.str() << '\n';
    }
}

void print_uffd_table(std::ostream& out, const UffdDemoResult& result) {
    out << "userfaultfd mode=" << result.mode << " length=" << detail::format_size(result.length)
        << " page_size=" << result.page_size << '\n';
    if (!result.available) {
        out << "unavailable: " << result.error << '\n';
        return;
    }
    out << "base=0x" << std::hex << result.base << std::dec << " events=" << result.events.size()
        << '\n';
    out << std::left << std::setw(18) << "OFFSET" << std::setw(18) << "ADDRESS" << std::setw(8)
        << "WRITE" << std::setw(8) << "WP"
        << "TIMESTAMP_NS\n";
    for (const UffdFaultEvent& event : result.events) {
        std::ostringstream offset;
        print_hex(offset, event.offset);
        std::ostringstream address;
        print_hex(address, event.address);
        out << std::left << std::setw(18) << offset.str() << std::setw(18) << address.str()
            << std::setw(8) << (event.write ? "yes" : "no") << std::setw(8)
            << (event.wp ? "yes" : "no") << event.timestamp_ns << '\n';
    }
}

void print_insights_table(std::ostream& out, const std::vector<Insight>& insights) {
    if (insights.empty()) {
        out << "No high-signal insights from the selected layers.\n";
        return;
    }
    out << std::left << std::setw(16) << "TYPE" << std::setw(10) << "SCORE" << std::setw(38)
        << "TARGET"
        << "EVIDENCE / SUGGESTION\n";
    for (const Insight& insight : insights) {
        std::ostringstream score;
        score << std::fixed << std::setprecision(2) << insight.score;
        out << std::left << std::setw(16) << insight.type << std::setw(10) << score.str()
            << std::setw(38) << insight.key << insight.evidence << "\n";
        out << std::setw(64) << "" << insight.suggestion << "\n";
    }
}

void print_growth_table(std::ostream& out, const GrowthReport& report) {
    out << "growth_check pid=" << report.pid << " samples=" << report.samples
        << " interval_ms=" << report.interval_ms
        << " monotonic_size=" << (report.monotonic_size ? "yes" : "no")
        << " monotonic_rss=" << (report.monotonic_rss ? "yes" : "no") << '\n';
    out << "size " << detail::format_size(report.first_size) << " -> "
        << detail::format_size(report.last_size) << ", rss "
        << detail::format_size(report.first_rss_kb * 1024) << " -> "
        << detail::format_size(report.last_rss_kb * 1024) << '\n';
    out << "trend size_slope="
        << detail::format_size(static_cast<uint64_t>(
               report.size_slope_bytes_per_sample > 0.0 ? report.size_slope_bytes_per_sample : 0.0))
        << "/sample r2=" << std::fixed << std::setprecision(3) << report.size_r2
        << " rss_slope=" << report.rss_slope_kb_per_sample << " KiB/sample r2=" << report.rss_r2
        << std::defaultfloat << '\n';
    out << std::left << std::setw(44) << "KIND/SOURCE" << std::right << std::setw(14)
        << "SIZE_DELTA" << std::setw(12) << "RSS_DELTA" << std::setw(12) << "PSS_DELTA"
        << std::setw(8) << "COUNT" << '\n';
    for (const GrowthBucket& bucket : report.buckets) {
        out << std::left << std::setw(44) << bucket.key << std::right << std::setw(14)
            << (bucket.size_delta >= 0 ? "+" : "")
            << detail::format_size(abs_delta(bucket.size_delta)) << std::setw(12)
            << (bucket.rss_delta >= 0 ? "+" : "")
            << detail::format_size(abs_delta(bucket.rss_delta) * 1024) << std::setw(12)
            << (bucket.pss_delta >= 0 ? "+" : "")
            << detail::format_size(abs_delta(bucket.pss_delta) * 1024) << std::setw(8)
            << bucket.count_delta << '\n';
    }
}

void print_pagemap_table(std::ostream& out, const PageMapReport& report) {
    out << "pagemap pid=" << report.pid << " range=0x" << std::hex << report.range_begin << "-0x"
        << report.range_end << std::dec << " page_size=" << report.page_size << '\n';
    if (!report.available) {
        out << "unavailable: " << report.error << '\n';
        return;
    }
    out << "total_pages=" << report.total_pages << " present=" << report.present_pages
        << " swapped=" << report.swapped_pages << " soft_dirty=" << report.soft_dirty_pages
        << " file_or_shared=" << report.file_or_shared_pages
        << " exclusive=" << report.exclusive_pages << '\n';
    out << "pfn_visible=" << (report.pfn_visible ? "yes" : "no")
        << " pfn_visible_pages=" << report.pfn_visible_pages << '\n';
}

void print_numa_table(std::ostream& out, const NumaReport& report) {
    out << "numa pid=" << report.pid << " range=0x" << std::hex << report.range_begin << "-0x"
        << report.range_end << std::dec << " page_size=" << report.page_size << '\n';
    if (!report.available) {
        out << "unavailable: " << report.error << '\n';
        return;
    }
    out << "total_pages=" << report.total_pages << " located_pages=" << report.located_pages
        << '\n';
    out << std::left << std::setw(12) << "NODE" << std::right << std::setw(12) << "PAGES" << '\n';
    for (const NumaNodeCount& node : report.nodes) {
        out << std::left << std::setw(12) << node.node << std::right << std::setw(12) << node.pages
            << '\n';
    }
    if (!report.statuses.empty()) {
        out << std::left << std::setw(12) << "STATUS" << std::right << std::setw(12) << "PAGES"
            << '\n';
        for (const NumaStatusCount& status : report.statuses) {
            out << std::left << std::setw(12) << status.status << std::right << std::setw(12)
                << status.pages << '\n';
        }
    }
}

void print_page_flags_table(std::ostream& out, const PageFlagsReport& report) {
    out << "page_flags pid=" << report.pid << " range=0x" << std::hex << report.range_begin << "-0x"
        << report.range_end << std::dec << " page_size=" << report.page_size << '\n';
    if (!report.available) {
        out << "unavailable: " << report.error << '\n';
        return;
    }
    out << "total_pages=" << report.total_pages << " present=" << report.present_pages
        << " pfn_visible=" << (report.pfn_visible ? "yes" : "no")
        << " pfn_visible_pages=" << report.pfn_visible_pages << '\n';
    out << std::left << std::setw(24) << "FLAG" << std::right << std::setw(12) << "PAGES" << '\n';
    for (const PageFlagCount& flag : report.flags) {
        out << std::left << std::setw(24) << flag.name << std::right << std::setw(12) << flag.pages
            << '\n';
    }
}

void print_clear_refs_table(std::ostream& out, const ClearRefsReport& report) {
    out << "clear_refs pid=" << report.pid << " mode=" << report.mode << '\n';
    if (!report.available) {
        out << "unavailable: " << report.error << '\n';
        return;
    }
    out << "cleared=yes\n";
}

void print_resource_limits_table(std::ostream& out, const ResourceLimitsReport& report) {
    out << "resource_limits pid=" << report.pid << '\n';
    if (!report.available) {
        out << "unavailable: " << report.error << '\n';
        return;
    }
    out << std::left << std::setw(20) << "LIMIT" << std::right << std::setw(16) << "SOFT"
        << std::setw(16) << "HARD" << '\n';
    for (const ResourceLimitEntry& limit : report.limits) {
        out << std::left << std::setw(20) << limit.name << std::right << std::setw(16)
            << (limit.soft_infinity ? "unlimited" : detail::format_size(limit.soft))
            << std::setw(16)
            << (limit.hard_infinity ? "unlimited" : detail::format_size(limit.hard)) << '\n';
    }
}

void print_reconcile_table(std::ostream& out, const ReconcileReport& report) {
    out << "reconcile pid=" << report.pid << " truth=" << report.truth_source
        << " observed_regions=" << report.observed_regions
        << " truth_regions=" << report.truth_regions << '\n';
    out << "missing=" << report.missing_regions << " extra=" << report.extra_regions
        << " metadata=" << report.metadata_mismatches << '\n';
    if (report.mismatches.empty()) {
        out << "No VMA mismatches.\n";
        return;
    }
    out << std::left << std::setw(12) << "TYPE" << std::setw(35) << "RANGE" << std::setw(44)
        << "OBSERVED"
        << "TRUTH\n";
    for (const ReconcileMismatch& mismatch : report.mismatches) {
        std::ostringstream range;
        range << std::hex << mismatch.begin << "-" << mismatch.end << std::dec;
        out << std::left << std::setw(12) << mismatch.type << std::setw(35) << range.str()
            << std::setw(44) << mismatch.observed << mismatch.truth << '\n';
    }
}

void print_snapshot_json(std::ostream& out, const Snapshot& snapshot) {
    out << "{";
    out << "\"pid\":" << snapshot.pid;
    out << ",\"timestamp_ns\":" << snapshot.timestamp_ns;
    out << ",\"regions\":[";
    for (size_t i = 0; i < snapshot.regions.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        print_region_json(out, snapshot.regions[i]);
    }
    out << "]}\n";
}

void print_reconcile_json(std::ostream& out, const ReconcileReport& report) {
    out << "{";
    out << "\"pid\":" << report.pid;
    out << ",\"truth_source\":\"" << json_escape(report.truth_source) << "\"";
    out << ",\"observed_regions\":" << report.observed_regions;
    out << ",\"truth_regions\":" << report.truth_regions;
    out << ",\"missing_regions\":" << report.missing_regions;
    out << ",\"extra_regions\":" << report.extra_regions;
    out << ",\"metadata_mismatches\":" << report.metadata_mismatches;
    out << ",\"mismatches\":[";
    for (size_t i = 0; i < report.mismatches.size(); ++i) {
        const ReconcileMismatch& mismatch = report.mismatches[i];
        if (i != 0) {
            out << ",";
        }
        out << "{";
        out << "\"type\":\"" << json_escape(mismatch.type) << "\"";
        out << ",\"begin\":\"0x" << std::hex << mismatch.begin << std::dec << "\"";
        out << ",\"end\":\"0x" << std::hex << mismatch.end << std::dec << "\"";
        out << ",\"observed\":\"" << json_escape(mismatch.observed) << "\"";
        out << ",\"truth\":\"" << json_escape(mismatch.truth) << "\"";
        out << "}";
    }
    out << "]}\n";
}

void print_residency_json(std::ostream& out, const ResidencyReport& report) {
    out << "{";
    out << "\"pid\":" << report.pid;
    out << ",\"page_size\":" << report.page_size;
    out << ",\"exact\":" << (report.exact ? "true" : "false");
    out << ",\"entries\":[";
    for (size_t i = 0; i < report.entries.size(); ++i) {
        const ResidencyEntry& entry = report.entries[i];
        if (i != 0) {
            out << ",";
        }
        out << "{";
        out << "\"begin\":\"0x" << std::hex << entry.begin << std::dec << "\"";
        out << ",\"end\":\"0x" << std::hex << entry.end << std::dec << "\"";
        out << ",\"key\":\"" << json_escape(entry.key) << "\"";
        out << ",\"total_pages\":" << entry.total_pages;
        out << ",\"resident_pages\":" << entry.resident_pages;
        out << ",\"resident_ratio\":" << std::fixed << std::setprecision(6) << entry.resident_ratio
            << std::defaultfloat;
        out << ",\"exact\":" << (entry.exact ? "true" : "false");
        out << ",\"note\":\"" << json_escape(entry.note) << "\"";
        out << "}";
    }
    out << "]}\n";
}

void print_cgroup_json(std::ostream& out, const CgroupMemoryHealth& health) {
    out << "{";
    out << "\"path\":\"" << json_escape(health.path) << "\"";
    out << ",\"current_bytes\":" << health.current_bytes;
    out << ",\"max_bytes\":" << health.max_bytes;
    out << ",\"has_limit\":" << (health.has_limit ? "true" : "false");
    out << ",\"usage_ratio\":" << std::fixed << std::setprecision(6) << health.usage_ratio
        << std::defaultfloat;
    out << ",\"anon_bytes\":" << health.anon_bytes;
    out << ",\"file_bytes\":" << health.file_bytes;
    out << ",\"kernel_stack_bytes\":" << health.kernel_stack_bytes;
    out << ",\"oom_events\":" << health.oom_events;
    out << ",\"oom_kill_events\":" << health.oom_kill_events;
    out << ",\"has_pressure\":" << (health.has_pressure ? "true" : "false");
    out << ",\"psi\":{";
    out << "\"some\":{\"avg10\":" << health.some.avg10 << ",\"avg60\":" << health.some.avg60
        << ",\"avg300\":" << health.some.avg300 << ",\"total\":" << health.some.total << "}";
    out << ",\"full\":{\"avg10\":" << health.full.avg10 << ",\"avg60\":" << health.full.avg60
        << ",\"avg300\":" << health.full.avg300 << ",\"total\":" << health.full.total << "}";
    out << "}";
    out << ",\"oom_risk\":" << std::fixed << std::setprecision(6) << health.oom_risk
        << std::defaultfloat;
    out << "}\n";
}

void print_perf_json(std::ostream& out, const PerfSampleReport& report) {
    out << "{";
    out << "\"pid\":" << report.pid;
    out << ",\"event\":\"" << json_escape(report.event) << "\"";
    out << ",\"duration_ms\":" << report.duration_ms;
    out << ",\"available\":" << (report.available ? "true" : "false");
    out << ",\"error\":\"" << json_escape(report.error) << "\"";
    out << ",\"perf_event_paranoid\":" << report.perf_event_paranoid;
    out << ",\"total_samples\":" << report.total_samples;
    out << ",\"lost_samples\":" << report.lost_samples;
    out << ",\"hotspots\":[";
    for (size_t i = 0; i < report.hotspots.size(); ++i) {
        const PerfHotspot& hotspot = report.hotspots[i];
        if (i != 0) {
            out << ",";
        }
        out << "{";
        out << "\"key\":\"" << json_escape(hotspot.key) << "\"";
        out << ",\"samples\":" << hotspot.samples;
        out << ",\"total_weight\":" << hotspot.total_weight;
        out << ",\"hotspot_ip\":\"0x" << std::hex << hotspot.hotspot_ip << std::dec << "\"";
        out << ",\"hotspot_addr\":\"0x" << std::hex << hotspot.hotspot_addr << std::dec << "\"";
        out << "}";
    }
    out << "]}\n";
}

void print_uffd_json(std::ostream& out, const UffdDemoResult& result) {
    out << "{";
    out << "\"available\":" << (result.available ? "true" : "false");
    out << ",\"error\":\"" << json_escape(result.error) << "\"";
    out << ",\"mode\":\"" << json_escape(result.mode) << "\"";
    out << ",\"page_size\":" << result.page_size;
    out << ",\"base\":\"0x" << std::hex << result.base << std::dec << "\"";
    out << ",\"length\":" << result.length;
    out << ",\"events\":[";
    for (size_t i = 0; i < result.events.size(); ++i) {
        const UffdFaultEvent& event = result.events[i];
        if (i != 0) {
            out << ",";
        }
        out << "{";
        out << "\"address\":\"0x" << std::hex << event.address << std::dec << "\"";
        out << ",\"offset\":\"0x" << std::hex << event.offset << std::dec << "\"";
        out << ",\"timestamp_ns\":" << event.timestamp_ns;
        out << ",\"write\":" << (event.write ? "true" : "false");
        out << ",\"wp\":" << (event.wp ? "true" : "false");
        out << "}";
    }
    out << "]}\n";
}

void print_insights_json(std::ostream& out, const std::vector<Insight>& insights) {
    out << "{\"insights\":[";
    for (size_t i = 0; i < insights.size(); ++i) {
        const Insight& insight = insights[i];
        if (i != 0) {
            out << ",";
        }
        out << "{";
        out << "\"type\":\"" << json_escape(insight.type) << "\"";
        out << ",\"key\":\"" << json_escape(insight.key) << "\"";
        out << ",\"score\":" << std::fixed << std::setprecision(6) << insight.score
            << std::defaultfloat;
        out << ",\"evidence\":\"" << json_escape(insight.evidence) << "\"";
        out << ",\"suggestion\":\"" << json_escape(insight.suggestion) << "\"";
        out << "}";
    }
    out << "]}\n";
}

void print_growth_json(std::ostream& out, const GrowthReport& report) {
    out << "{";
    out << "\"pid\":" << report.pid;
    out << ",\"samples\":" << report.samples;
    out << ",\"interval_ms\":" << report.interval_ms;
    out << ",\"monotonic_size\":" << (report.monotonic_size ? "true" : "false");
    out << ",\"monotonic_rss\":" << (report.monotonic_rss ? "true" : "false");
    out << ",\"size_slope_bytes_per_sample\":" << report.size_slope_bytes_per_sample;
    out << ",\"rss_slope_kb_per_sample\":" << report.rss_slope_kb_per_sample;
    out << ",\"size_r2\":" << report.size_r2;
    out << ",\"rss_r2\":" << report.rss_r2;
    out << ",\"first_size\":" << report.first_size;
    out << ",\"last_size\":" << report.last_size;
    out << ",\"first_rss_kb\":" << report.first_rss_kb;
    out << ",\"last_rss_kb\":" << report.last_rss_kb;
    out << ",\"buckets\":[";
    for (size_t i = 0; i < report.buckets.size(); ++i) {
        const GrowthBucket& bucket = report.buckets[i];
        if (i != 0) {
            out << ",";
        }
        out << "{";
        out << "\"key\":\"" << json_escape(bucket.key) << "\"";
        out << ",\"size_delta\":" << bucket.size_delta;
        out << ",\"rss_delta\":" << bucket.rss_delta;
        out << ",\"pss_delta\":" << bucket.pss_delta;
        out << ",\"count_delta\":" << bucket.count_delta;
        out << "}";
    }
    out << "]}\n";
}

void print_pagemap_json(std::ostream& out, const PageMapReport& report) {
    out << "{";
    out << "\"pid\":" << report.pid;
    out << ",\"available\":" << (report.available ? "true" : "false");
    out << ",\"error\":\"" << json_escape(report.error) << "\"";
    out << ",\"page_size\":" << report.page_size;
    out << ",\"range_begin\":\"0x" << std::hex << report.range_begin << std::dec << "\"";
    out << ",\"range_end\":\"0x" << std::hex << report.range_end << std::dec << "\"";
    out << ",\"total_pages\":" << report.total_pages;
    out << ",\"present_pages\":" << report.present_pages;
    out << ",\"swapped_pages\":" << report.swapped_pages;
    out << ",\"soft_dirty_pages\":" << report.soft_dirty_pages;
    out << ",\"file_or_shared_pages\":" << report.file_or_shared_pages;
    out << ",\"exclusive_pages\":" << report.exclusive_pages;
    out << ",\"pfn_visible_pages\":" << report.pfn_visible_pages;
    out << ",\"pfn_visible\":" << (report.pfn_visible ? "true" : "false");
    out << "}\n";
}

void print_numa_json(std::ostream& out, const NumaReport& report) {
    out << "{";
    out << "\"pid\":" << report.pid;
    out << ",\"available\":" << (report.available ? "true" : "false");
    out << ",\"error\":\"" << json_escape(report.error) << "\"";
    out << ",\"page_size\":" << report.page_size;
    out << ",\"range_begin\":\"0x" << std::hex << report.range_begin << std::dec << "\"";
    out << ",\"range_end\":\"0x" << std::hex << report.range_end << std::dec << "\"";
    out << ",\"total_pages\":" << report.total_pages;
    out << ",\"located_pages\":" << report.located_pages;
    out << ",\"nodes\":[";
    for (size_t i = 0; i < report.nodes.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        out << "{\"node\":" << report.nodes[i].node << ",\"pages\":" << report.nodes[i].pages
            << "}";
    }
    out << "]";
    out << ",\"statuses\":[";
    for (size_t i = 0; i < report.statuses.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        out << "{\"status\":" << report.statuses[i].status
            << ",\"pages\":" << report.statuses[i].pages << "}";
    }
    out << "]";
    out << "}\n";
}

void print_page_flags_json(std::ostream& out, const PageFlagsReport& report) {
    out << "{";
    out << "\"pid\":" << report.pid;
    out << ",\"available\":" << (report.available ? "true" : "false");
    out << ",\"error\":\"" << json_escape(report.error) << "\"";
    out << ",\"page_size\":" << report.page_size;
    out << ",\"range_begin\":\"0x" << std::hex << report.range_begin << std::dec << "\"";
    out << ",\"range_end\":\"0x" << std::hex << report.range_end << std::dec << "\"";
    out << ",\"total_pages\":" << report.total_pages;
    out << ",\"present_pages\":" << report.present_pages;
    out << ",\"pfn_visible_pages\":" << report.pfn_visible_pages;
    out << ",\"pfn_visible\":" << (report.pfn_visible ? "true" : "false");
    out << ",\"flags\":[";
    for (size_t i = 0; i < report.flags.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        out << "{\"name\":\"" << json_escape(report.flags[i].name)
            << "\",\"pages\":" << report.flags[i].pages << "}";
    }
    out << "]";
    out << "}\n";
}

void print_clear_refs_json(std::ostream& out, const ClearRefsReport& report) {
    out << "{";
    out << "\"pid\":" << report.pid;
    out << ",\"available\":" << (report.available ? "true" : "false");
    out << ",\"error\":\"" << json_escape(report.error) << "\"";
    out << ",\"mode\":\"" << json_escape(report.mode) << "\"";
    out << "}\n";
}

void print_resource_limits_json(std::ostream& out, const ResourceLimitsReport& report) {
    out << "{";
    out << "\"pid\":" << report.pid;
    out << ",\"available\":" << (report.available ? "true" : "false");
    out << ",\"error\":\"" << json_escape(report.error) << "\"";
    out << ",\"limits\":[";
    for (size_t i = 0; i < report.limits.size(); ++i) {
        const ResourceLimitEntry& limit = report.limits[i];
        if (i != 0) {
            out << ",";
        }
        out << "{";
        out << "\"name\":\"" << json_escape(limit.name) << "\"";
        out << ",\"soft\":" << limit.soft;
        out << ",\"hard\":" << limit.hard;
        out << ",\"soft_infinity\":" << (limit.soft_infinity ? "true" : "false");
        out << ",\"hard_infinity\":" << (limit.hard_infinity ? "true" : "false");
        out << "}";
    }
    out << "]}\n";
}

void print_events_json(std::ostream& out, const std::vector<MapEvent>& events) {
    out << "[";
    for (size_t i = 0; i < events.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        print_event_json_item(out, events[i]);
    }
    out << "]\n";
}

void print_diff_json(std::ostream& out, const std::vector<DiffEntry>& diff) {
    out << "[";
    for (size_t i = 0; i < diff.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        out << "{";
        out << "\"key\":\"" << json_escape(diff[i].key) << "\"";
        out << ",\"size_delta\":" << diff[i].size_delta;
        out << ",\"rss_delta\":" << diff[i].rss_delta;
        out << ",\"pss_delta\":" << diff[i].pss_delta;
        out << ",\"count_delta\":" << diff[i].count_delta;
        out << "}";
    }
    out << "]\n";
}

}  // namespace mmv
