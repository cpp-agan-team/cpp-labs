#include "decoder_internal.hpp"

#include <cstdint>
#include <string>
#include <sys/prctl.h>
#include <utility>

namespace mini_strace {
namespace detail {
namespace {

std::string format_prctl_option(std::uint64_t option) {
    switch (static_cast<int>(option)) {
#ifdef PR_SET_PDEATHSIG
        case PR_SET_PDEATHSIG:
            return "PR_SET_PDEATHSIG";
#endif
#ifdef PR_GET_PDEATHSIG
        case PR_GET_PDEATHSIG:
            return "PR_GET_PDEATHSIG";
#endif
#ifdef PR_SET_NAME
        case PR_SET_NAME:
            return "PR_SET_NAME";
#endif
#ifdef PR_GET_NAME
        case PR_GET_NAME:
            return "PR_GET_NAME";
#endif
#ifdef PR_SET_NO_NEW_PRIVS
        case PR_SET_NO_NEW_PRIVS:
            return "PR_SET_NO_NEW_PRIVS";
#endif
#ifdef PR_GET_NO_NEW_PRIVS
        case PR_GET_NO_NEW_PRIVS:
            return "PR_GET_NO_NEW_PRIVS";
#endif
#ifdef PR_SET_SECCOMP
        case PR_SET_SECCOMP:
            return "PR_SET_SECCOMP";
#endif
#ifdef PR_GET_SECCOMP
        case PR_GET_SECCOMP:
            return "PR_GET_SECCOMP";
#endif
        default:
            return std::to_string(option);
    }
}

std::string format_futex_op(std::uint64_t op) {
    const int command = static_cast<int>(op) & 0x7f;
    switch (command) {
        case 0:
            return "FUTEX_WAIT";
        case 1:
            return "FUTEX_WAKE";
        case 2:
            return "FUTEX_FD";
        case 3:
            return "FUTEX_REQUEUE";
        case 4:
            return "FUTEX_CMP_REQUEUE";
        case 5:
            return "FUTEX_WAKE_OP";
        case 6:
            return "FUTEX_LOCK_PI";
        case 7:
            return "FUTEX_UNLOCK_PI";
        case 8:
            return "FUTEX_TRYLOCK_PI";
        case 9:
            return "FUTEX_WAIT_BITSET";
        case 10:
            return "FUTEX_WAKE_BITSET";
        default:
            return std::to_string(op);
    }
}

}  // namespace

bool decode_seccomp_event(SyscallEvent& event) {
    const std::string& name = event.name;
    if (name == "prctl") {
        add_arg(event, "option", format_prctl_option(event.raw_args[0]), event.raw_args[0]);
        add_arg(event, "arg2", format_hex(event.raw_args[1]), event.raw_args[1]);
        add_arg(event, "arg3", format_hex(event.raw_args[2]), event.raw_args[2]);
        add_arg(event, "arg4", format_hex(event.raw_args[3]), event.raw_args[3]);
        add_arg(event, "arg5", format_hex(event.raw_args[4]), event.raw_args[4]);
        return true;
    }
    if (name == "futex") {
        add_arg(event, "uaddr", format_hex(event.raw_args[0]), event.raw_args[0]);
        add_arg(event, "op", format_futex_op(event.raw_args[1]), event.raw_args[1]);
        add_arg(event, "val", std::to_string(event.raw_args[2]), event.raw_args[2]);
        add_arg(event, "timeout", format_hex(event.raw_args[3]), event.raw_args[3]);
        return true;
    }
    return false;
}

}  // namespace detail
}  // namespace mini_strace
