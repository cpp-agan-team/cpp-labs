#include <unistd.h>

int main() {
    const char msg[] = "hello\n";
    ::write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    return 0;
}
