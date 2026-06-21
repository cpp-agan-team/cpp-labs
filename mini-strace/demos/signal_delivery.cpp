#include <csignal>
#include <unistd.h>

namespace {

volatile sig_atomic_t seen = 0;

void handle_usr1(int) {
    seen = 1;
}

}  // namespace

int main() {
    struct sigaction action {};
    action.sa_handler = handle_usr1;
    sigemptyset(&action.sa_mask);
    if (::sigaction(SIGUSR1, &action, nullptr) != 0) {
        return 1;
    }
    if (::kill(::getpid(), SIGUSR1) != 0) {
        return 1;
    }
    for (int i = 0; i < 100000 && seen == 0; ++i) {
    }
    return seen == 1 ? 0 : 2;
}
