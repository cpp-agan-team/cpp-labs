#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
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
    const char* path = argc > 1 ? argv[1] : "/tmp/mem_map_viewer_file_mapping.bin";
    const int seconds = argc > 2 ? std::atoi(argv[2]) : 0;
    constexpr size_t kSize = 8 * 1024 * 1024;

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    int fd = ::open(path, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        std::cerr << "open failed: " << std::strerror(errno) << '\n';
        return 1;
    }
    if (::ftruncate(fd, static_cast<off_t>(kSize)) != 0) {
        std::cerr << "ftruncate failed: " << std::strerror(errno) << '\n';
        ::close(fd);
        return 1;
    }

    void* ptr = ::mmap(nullptr, kSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        std::cerr << "mmap failed: " << std::strerror(errno) << '\n';
        ::close(fd);
        return 1;
    }

    std::memset(ptr, 0x31, kSize);
    std::cout << "file_mapping_demo pid=" << getpid() << " path=" << path << "\n"
              << "Run: mem-map-viewer --pid " << getpid() << " --summary --with-smaps\n"
              << "Trace: mem-map-viewer --trace " << argv[0] << " " << path << " 1 --events\n"
              << std::flush;

    int elapsed = 0;
    while (!g_stop && (seconds <= 0 || elapsed < seconds)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        ++elapsed;
    }

    ::munmap(ptr, kSize);
    ::close(fd);
    return 0;
}
