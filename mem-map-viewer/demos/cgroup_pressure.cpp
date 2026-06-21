#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

volatile std::sig_atomic_t g_stop = 0;

void on_signal(int) {
    g_stop = 1;
}

void touch_pages(unsigned char* ptr, size_t length, size_t page) {
    for (size_t offset = 0; offset < length; offset += page) {
        ptr[offset] = static_cast<unsigned char>(offset / page);
    }
}

struct Mapping {
    void* ptr = nullptr;
    size_t length = 0;
};

}  // namespace

int main(int argc, char** argv) {
    const size_t total_bytes =
        argc > 1 ? static_cast<size_t>(std::strtoull(argv[1], nullptr, 10)) : 128 * 1024 * 1024;
    const size_t chunk_bytes =
        argc > 2 ? static_cast<size_t>(std::strtoull(argv[2], nullptr, 10)) : 8 * 1024 * 1024;
    const int hold_seconds = argc > 3 ? std::atoi(argv[3]) : 0;
    const size_t page = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    if (total_bytes == 0 || chunk_bytes == 0) {
        std::cerr << "total and chunk bytes must be positive\n";
        return 1;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::cout << "cgroup_pressure_demo pid=" << getpid() << " target=" << total_bytes
              << " chunk=" << chunk_bytes << "\n"
              << "Run: mem-map-viewer --cgroup self --psi --oom-risk --watch\n"
              << std::flush;

    std::vector<Mapping> mappings;
    size_t allocated = 0;
    while (!g_stop && allocated < total_bytes) {
        const size_t length = std::min(chunk_bytes, total_bytes - allocated);
        void* mapping =
            ::mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED) {
            std::cerr << "mmap failed after " << allocated << " bytes: " << std::strerror(errno)
                      << '\n';
            break;
        }
        touch_pages(static_cast<unsigned char*>(mapping), length, page);
        mappings.push_back(Mapping{mapping, length});
        allocated += length;
        std::cout << "allocated_bytes=" << allocated << '\n' << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (hold_seconds > 0) {
        for (int i = 0; i < hold_seconds && !g_stop; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } else {
        while (!g_stop) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    for (const Mapping& mapping : mappings) {
        ::munmap(mapping.ptr, mapping.length);
    }
    return 0;
}
