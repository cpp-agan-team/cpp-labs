#include <cerrno>
#include <cstdint>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int main() {
    std::int32_t word = 0;
    timespec timeout{};
    timeout.tv_nsec = 1000000;

    const long rc = ::syscall(SYS_futex, &word, FUTEX_WAIT, 0, &timeout, nullptr, 0);
    if (rc == -1 && errno == ETIMEDOUT) {
        return 0;
    }
    return rc == 0 ? 0 : 1;
}
