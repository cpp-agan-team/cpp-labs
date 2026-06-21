#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

std::atomic<bool> g_stop{false};

void on_signal(int) {
    g_stop.store(true);
}

void worker(size_t stack_touch_bytes) {
    std::vector<char> stack_touch(stack_touch_bytes, 0x42);
    while (!g_stop.load()) {
        for (char& value : stack_touch) {
            value ^= 1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

}  // namespace

int main(int argc, char** argv) {
    const int thread_count = argc > 1 ? std::atoi(argv[1]) : 16;
    const size_t stack_touch_bytes =
        argc > 2 ? static_cast<size_t>(std::strtoull(argv[2], nullptr, 10)) : 256 * 1024;
    const int seconds = argc > 3 ? std::atoi(argv[3]) : 0;

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::cout << "thread_stack_growth_demo pid=" << getpid() << " threads=" << thread_count
              << "\nRun: mem-map-viewer --pid " << getpid() << " --summary --with-smaps\n"
              << "Trace: mem-map-viewer --trace " << argv[0] << " " << thread_count << " "
              << stack_touch_bytes << " 2 --events\n"
              << std::flush;

    std::vector<std::thread> threads;
    threads.reserve(static_cast<size_t>(thread_count));
    for (int i = 0; i < thread_count; ++i) {
        threads.emplace_back(worker, stack_touch_bytes);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    int elapsed = 0;
    while (!g_stop.load() && (seconds <= 0 || elapsed < seconds)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        ++elapsed;
    }
    g_stop.store(true);
    for (std::thread& thread : threads) {
        thread.join();
    }
    return 0;
}
