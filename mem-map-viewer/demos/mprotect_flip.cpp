#include <chrono>
#include <csignal>
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

}  // namespace

int main(int argc, char** argv) {
    const size_t region_size = 2 * 1024 * 1024;
    const int interval_ms = argc > 1 ? std::atoi(argv[1]) : 700;
    const int iterations = argc > 2 ? std::atoi(argv[2]) : 0;

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    void* ptr =
        ::mmap(nullptr, region_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        std::cerr << "mmap failed: " << std::strerror(errno) << '\n';
        return 1;
    }
    std::memset(ptr, 0xcc, region_size);

    std::cout << "mprotect_flip_demo pid=" << getpid() << " addr=" << ptr << "\n"
              << "Run: mem-map-viewer --trace " << argv[0] << " " << interval_ms << " 6 --events\n"
              << std::flush;

    bool writable = true;
    int flips = 0;
    while (!g_stop && (iterations <= 0 || flips < iterations)) {
        const int prot = writable ? PROT_READ : (PROT_READ | PROT_WRITE);
        if (::mprotect(ptr, region_size, prot) != 0) {
            std::cerr << "mprotect failed: " << std::strerror(errno) << '\n';
            return 1;
        }
        writable = !writable;
        ++flips;
        std::cout << "permission=" << (writable ? "rw" : "r") << '\n' << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }

    ::munmap(ptr, region_size);
    return 0;
}
