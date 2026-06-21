#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>

namespace {

volatile std::sig_atomic_t g_stop = 0;

void on_signal(int) {
    g_stop = 1;
}

uint64_t next_index(uint64_t value, uint64_t pages) {
    return (value * 1103515245ULL + 12345ULL) % pages;
}

}  // namespace

int main(int argc, char** argv) {
    const size_t map_size =
        argc > 1 ? static_cast<size_t>(std::strtoull(argv[1], nullptr, 10)) : 512 * 1024 * 1024;
    const int seconds = argc > 2 ? std::atoi(argv[2]) : 0;
    const size_t page = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    const size_t pages = map_size / page;
    if (pages == 0) {
        std::cerr << "map size is too small\n";
        return 1;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    void* mapping =
        ::mmap(nullptr, pages * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        std::cerr << "mmap failed: " << std::strerror(errno) << '\n';
        return 1;
    }

    auto* bytes = static_cast<unsigned char*>(mapping);
    for (size_t i = 0; i < pages; ++i) {
        bytes[i * page] = static_cast<unsigned char>(i);
    }

    std::cout << "tlb_thrash_demo pid=" << getpid() << " mapped=" << pages * page
              << " pages=" << pages << "\n"
              << "Run: mem-map-viewer --pid " << getpid()
              << " --perf-sample --perf-event dtlb-miss --duration-ms 5000\n"
              << std::flush;

    uint64_t index = 1;
    uint64_t rounds = 0;
    const auto start = std::chrono::steady_clock::now();
    while (!g_stop) {
        for (size_t i = 0; i < pages; ++i) {
            index = next_index(index, pages);
            bytes[index * page] += 1;
        }
        ++rounds;
        if (seconds > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start);
            if (elapsed.count() >= seconds) {
                break;
            }
        }
    }

    std::cout << "rounds=" << rounds << '\n';
    ::munmap(mapping, pages * page);
    return 0;
}
