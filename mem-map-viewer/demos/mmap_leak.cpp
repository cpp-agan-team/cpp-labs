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

}  // namespace

int main(int argc, char** argv) {
    const size_t chunk_size =
        argc > 1 ? static_cast<size_t>(std::strtoull(argv[1], nullptr, 10)) : 4 * 1024 * 1024;
    const int interval_ms = argc > 2 ? std::atoi(argv[2]) : 500;
    const size_t max_chunks =
        argc > 3 ? static_cast<size_t>(std::strtoull(argv[3], nullptr, 10)) : 0;

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::vector<void*> mappings;
    std::cout << "mmap_leak_demo pid=" << getpid() << "\n"
              << "Run: mem-map-viewer --pid " << getpid() << " --summary --with-smaps\n"
              << "Trace: mem-map-viewer --trace " << argv[0] << " " << chunk_size << " "
              << interval_ms << " 4 --events\n"
              << std::flush;

    while (!g_stop && (max_chunks == 0 || mappings.size() < max_chunks)) {
        void* ptr =
            ::mmap(nullptr, chunk_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED) {
            std::cerr << "mmap failed: " << std::strerror(errno) << '\n';
            return 1;
        }
        std::memset(ptr, 0x5a, chunk_size);
        mappings.push_back(ptr);
        std::cout << "mapped_chunks=" << mappings.size()
                  << " total_bytes=" << mappings.size() * chunk_size << '\n'
                  << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }

    return 0;
}
