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

}  // namespace

int main(int argc, char** argv) {
    const size_t map_size =
        argc > 1 ? static_cast<size_t>(std::strtoull(argv[1], nullptr, 10)) : 256 * 1024 * 1024;
    const size_t touch_bytes =
        argc > 2 ? static_cast<size_t>(std::strtoull(argv[2], nullptr, 10)) : 1024 * 1024;
    const int seconds = argc > 3 ? std::atoi(argv[3]) : 0;

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    void* ptr =
        ::mmap(nullptr, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        std::cerr << "mmap failed: " << std::strerror(errno) << '\n';
        return 1;
    }

    const size_t limit = touch_bytes < map_size ? touch_bytes : map_size;
    for (size_t offset = 0; offset < limit;
         offset += static_cast<size_t>(::sysconf(_SC_PAGESIZE))) {
        static_cast<char*>(ptr)[offset] = 0x7a;
    }

    std::cout << "lazy_touch_demo pid=" << getpid() << " mapped=" << map_size
              << " touched=" << limit << "\n"
              << "Run: mem-map-viewer --pid " << getpid() << " --residency --with-smaps\n"
              << std::flush;

    int elapsed = 0;
    while (!g_stop && (seconds <= 0 || elapsed < seconds)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        ++elapsed;
    }

    ::munmap(ptr, map_size);
    return 0;
}
