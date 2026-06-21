#include <cerrno>
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>

namespace {

volatile sig_atomic_t seen = 0;

void handle_usr1(int) {
    seen = 1;
}

}  // namespace

int main() {
    int pipe_fds[2] = {-1, -1};
    if (::pipe(pipe_fds) != 0) {
        return 1;
    }

    struct sigaction action {};
    action.sa_handler = handle_usr1;
    sigemptyset(&action.sa_mask);
    if (::sigaction(SIGUSR1, &action, nullptr) != 0) {
        return 1;
    }

    const pid_t child = ::fork();
    if (child < 0) {
        return 1;
    }
    if (child == 0) {
        ::close(pipe_fds[0]);
        ::close(pipe_fds[1]);
        ::usleep(10000);
        ::kill(::getppid(), SIGUSR1);
        _exit(0);
    }

    char byte = 0;
    const ssize_t nread = ::read(pipe_fds[0], &byte, sizeof(byte));
    const bool interrupted = nread == -1 && errno == EINTR && seen == 1;

    ::close(pipe_fds[0]);
    ::close(pipe_fds[1]);
    int status = 0;
    ::waitpid(child, &status, 0);
    return interrupted ? 0 : 2;
}
