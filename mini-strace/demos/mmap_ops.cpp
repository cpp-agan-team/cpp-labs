#include <sys/mman.h>
#include <unistd.h>

int main() {
    constexpr int kLength = 4096;
    void* ptr = ::mmap(nullptr, kLength, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        return 1;
    }
    ::mprotect(ptr, kLength, PROT_READ);
    ::munmap(ptr, kLength);
    return 0;
}
