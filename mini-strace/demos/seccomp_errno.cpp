#include <cerrno>
#include <cstddef>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

int install_getpid_errno_filter() {
    sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    sock_fprog program{};
    program.len = static_cast<unsigned short>(sizeof(code) / sizeof(code[0]));
    program.filter = code;

    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return -1;
    }
    return ::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

}  // namespace

int main() {
    if (install_getpid_errno_filter() != 0) {
        return 1;
    }

    errno = 0;
    const long rc = ::syscall(SYS_getpid);
    if (rc != -1 || errno != EPERM) {
        return 2;
    }
    return 0;
}
