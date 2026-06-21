#include <csignal>

int main() {
    ::raise(SIGTERM);
    return 1;
}
