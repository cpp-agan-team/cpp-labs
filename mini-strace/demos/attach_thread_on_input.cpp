#include <cerrno>
#include <cstddef>
#include <thread>
#include <unistd.h>

namespace {

bool write_all(const char* text) {
    const char* cursor = text;
    std::size_t remaining = 0;
    while (text[remaining] != '\0') {
        ++remaining;
    }
    while (remaining > 0) {
        const ssize_t written = ::write(STDOUT_FILENO, cursor, remaining);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        cursor += written;
        remaining -= static_cast<std::size_t>(written);
    }
    return true;
}

}  // namespace

int main() {
    if (!write_all("ready\n")) {
        return 1;
    }

    char trigger = 0;
    ssize_t nread = 0;
    while ((nread = ::read(STDIN_FILENO, &trigger, 1)) < 0) {
        if (errno != EINTR) {
            return 1;
        }
    }
    if (nread != 1) {
        return 1;
    }

    std::thread worker([] { (void)write_all("attach-thread\n"); });
    const bool main_ok = write_all("attach-main\n");
    worker.join();
    return main_ok ? 0 : 1;
}
