#include "internal.hpp"
#include "unique_fd.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <linux/perf_event.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <thread>
#include <unistd.h>

#ifndef SYS_perf_event_open
#ifdef __NR_perf_event_open
#define SYS_perf_event_open __NR_perf_event_open
#endif
#endif

namespace mmv {
namespace {

uint64_t page_size() {
    long value = ::sysconf(_SC_PAGESIZE);
    if (value <= 0) {
        throw std::runtime_error("sysconf(_SC_PAGESIZE) failed");
    }
    return static_cast<uint64_t>(value);
}

int read_paranoid() {
    std::ifstream input("/proc/sys/kernel/perf_event_paranoid");
    int value = 0;
    input >> value;
    return value;
}

uint64_t hardware_event_config(const std::string& event) {
    if (event == "cache-miss") {
        return PERF_COUNT_HW_CACHE_LL | (PERF_COUNT_HW_CACHE_OP_READ << 8U) |
               (PERF_COUNT_HW_CACHE_RESULT_MISS << 16U);
    }
    return PERF_COUNT_HW_CACHE_DTLB | (PERF_COUNT_HW_CACHE_OP_READ << 8U) |
           (PERF_COUNT_HW_CACHE_RESULT_MISS << 16U);
}

std::string normalize_event(const std::string& event) {
    if (event == "cache-miss" || event == "cpu-clock") {
        return event;
    }
    return "dtlb-miss";
}

uint64_t sample_type_for(const std::string& event) {
    if (event == "cpu-clock") {
        return PERF_SAMPLE_IP | PERF_SAMPLE_TID;
    }
    return PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ADDR | PERF_SAMPLE_WEIGHT;
}

UniqueFd open_sampler(int pid, const std::string& event) {
    perf_event_attr attr{};
    attr.size = sizeof(attr);
    if (event == "cpu-clock") {
        attr.type = PERF_TYPE_SOFTWARE;
        attr.config = PERF_COUNT_SW_CPU_CLOCK;
        attr.sample_period = 1000000;
    } else {
        attr.type = PERF_TYPE_HW_CACHE;
        attr.config = hardware_event_config(event);
        attr.sample_period = 1000;
    }
    attr.sample_type = sample_type_for(event);
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.inherit = event == "cpu-clock" ? 0 : 1;

#ifdef SYS_perf_event_open
    return UniqueFd(static_cast<int>(::syscall(SYS_perf_event_open, &attr, pid, -1, -1, 0)));
#else
    errno = ENOSYS;
    return UniqueFd();
#endif
}

struct MmapView {
    void* base = MAP_FAILED;
    size_t size = 0;

    MmapView() = default;
    ~MmapView() {
        if (base != MAP_FAILED) {
            ::munmap(base, size);
        }
    }

    MmapView(const MmapView&) = delete;
    MmapView& operator=(const MmapView&) = delete;
};

void copy_from_ring(const char* data, size_t data_size, uint64_t pos, void* out, size_t len) {
    size_t offset = static_cast<size_t>(pos % data_size);
    size_t first = std::min(len, data_size - offset);
    std::memcpy(out, data + offset, first);
    if (first < len) {
        std::memcpy(static_cast<char*>(out) + first, data, len - first);
    }
}

uint64_t read_u64(const unsigned char** cursor, const unsigned char* end) {
    if (static_cast<size_t>(end - *cursor) < sizeof(uint64_t)) {
        return 0;
    }
    uint64_t value = 0;
    std::memcpy(&value, *cursor, sizeof(value));
    *cursor += sizeof(value);
    return value;
}

uint32_t read_u32(const unsigned char** cursor, const unsigned char* end) {
    if (static_cast<size_t>(end - *cursor) < sizeof(uint32_t)) {
        return 0;
    }
    uint32_t value = 0;
    std::memcpy(&value, *cursor, sizeof(value));
    *cursor += sizeof(value);
    return value;
}

std::string region_for_addr(const detail::RegionIndex& regions, uint64_t addr) {
    const Region* region = regions.find(addr);
    if (!region) {
        return "[unknown]";
    }
    return detail::region_key(*region);
}

PerfHotspot& bucket_for(std::vector<PerfHotspot>* buckets, const std::string& key) {
    auto it = std::find_if(buckets->begin(), buckets->end(),
                           [&](const PerfHotspot& item) { return item.key == key; });
    if (it != buckets->end()) {
        return *it;
    }
    PerfHotspot hotspot;
    hotspot.key = key;
    buckets->push_back(std::move(hotspot));
    return buckets->back();
}

void parse_samples(const detail::RegionIndex& regions, perf_event_mmap_page* meta,
                   size_t meta_page_size, PerfSampleReport* report) {
    const char* data = reinterpret_cast<const char*>(meta) + meta_page_size;
    const size_t data_size = static_cast<size_t>(meta->data_size);
    uint64_t tail = meta->data_tail;
    uint64_t head = meta->data_head;
    __sync_synchronize();

    while (tail + sizeof(perf_event_header) <= head) {
        perf_event_header header{};
        copy_from_ring(data, data_size, tail, &header, sizeof(header));
        if (header.size < sizeof(header) || tail + header.size > head || header.size > data_size) {
            break;
        }

        std::vector<unsigned char> body(header.size - sizeof(header));
        copy_from_ring(data, data_size, tail + sizeof(header), body.data(), body.size());
        if (header.type == PERF_RECORD_SAMPLE) {
            const unsigned char* cursor = body.data();
            const unsigned char* end = body.data() + body.size();
            const uint64_t ip = read_u64(&cursor, end);
            read_u32(&cursor, end);  // pid
            read_u32(&cursor, end);  // tid
            uint64_t addr = 0;
            uint64_t weight = 0;
            if (report->event != "cpu-clock") {
                addr = read_u64(&cursor, end);
                weight = read_u64(&cursor, end);
            }

            std::string key = region_for_addr(regions, addr != 0 ? addr : ip);
            PerfHotspot& hotspot = bucket_for(&report->hotspots, key);
            ++hotspot.samples;
            hotspot.total_weight += weight;
            hotspot.hotspot_ip = ip;
            hotspot.hotspot_addr = addr;
            ++report->total_samples;
        } else if (header.type == PERF_RECORD_LOST) {
            const unsigned char* cursor = body.data();
            const unsigned char* end = body.data() + body.size();
            read_u64(&cursor, end);  // event id
            report->lost_samples += read_u64(&cursor, end);
        }
        tail += header.size;
    }
    meta->data_tail = tail;
}

void drain_samples_for(const detail::RegionIndex& regions, perf_event_mmap_page* meta,
                       size_t meta_page_size, int duration_ms, PerfSampleReport* report) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(duration_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        parse_samples(regions, meta, meta_page_size, report);
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            break;
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        std::this_thread::sleep_for(std::min(std::chrono::milliseconds(50), remaining));
    }
}

}  // namespace

PerfSampleReport sample_perf_event(const Snapshot& snapshot, const std::string& event,
                                   int duration_ms) {
    PerfSampleReport report;
    report.pid = snapshot.pid;
    report.event = normalize_event(event);
    report.duration_ms = duration_ms;
    report.perf_event_paranoid = read_paranoid();
    detail::RegionIndex regions(snapshot.regions);

    UniqueFd fd = open_sampler(snapshot.pid, report.event);
    if (!fd) {
        report.error = std::string("perf_event_open failed: ") + std::strerror(errno);
        return report;
    }

    const uint64_t page = page_size();
    constexpr size_t kDataPages = 8;
    MmapView view;
    view.size = static_cast<size_t>(page) * (1 + kDataPages);
    view.base = ::mmap(nullptr, view.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0);
    if (view.base == MAP_FAILED) {
        report.error = std::string("perf mmap failed: ") + std::strerror(errno);
        return report;
    }

    auto* meta = static_cast<perf_event_mmap_page*>(view.base);
    if (::ioctl(fd.get(), PERF_EVENT_IOC_RESET, 0) != 0 ||
        ::ioctl(fd.get(), PERF_EVENT_IOC_ENABLE, 0) != 0) {
        report.error = std::string("perf enable failed: ") + std::strerror(errno);
        return report;
    }

    drain_samples_for(regions, meta, static_cast<size_t>(page), duration_ms, &report);
    ::ioctl(fd.get(), PERF_EVENT_IOC_DISABLE, 0);

    parse_samples(regions, meta, static_cast<size_t>(page), &report);
    std::sort(report.hotspots.begin(), report.hotspots.end(),
              [](const PerfHotspot& lhs, const PerfHotspot& rhs) {
                  if (lhs.samples != rhs.samples) {
                      return lhs.samples > rhs.samples;
                  }
                  return lhs.key < rhs.key;
              });
    report.available = true;
    return report;
}

}  // namespace mmv
