#include <atomic>
#include <thread>
#include <unistd.h>

int main() {
    std::atomic<bool> worker_can_write{false};
    std::thread worker([&] {
        while (!worker_can_write.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        const char message[] = "worker\n";
        ::write(STDOUT_FILENO, message, sizeof(message) - 1);
    });

    worker_can_write.store(true, std::memory_order_release);
    const char message[] = "main\n";
    ::write(STDOUT_FILENO, message, sizeof(message) - 1);
    worker.join();
    return 0;
}
