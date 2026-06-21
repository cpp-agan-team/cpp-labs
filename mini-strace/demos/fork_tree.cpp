#include <sys/wait.h>
#include <unistd.h>

int main() {
    const pid_t child = ::fork();
    if (child == 0) {
        const char msg[] = "child\n";
        ::write(STDOUT_FILENO, msg, sizeof(msg) - 1);
        _exit(0);
    }
    const char msg[] = "parent\n";
    ::write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    if (child > 0) {
        int status = 0;
        ::waitpid(child, &status, 0);
    }
    return 0;
}
