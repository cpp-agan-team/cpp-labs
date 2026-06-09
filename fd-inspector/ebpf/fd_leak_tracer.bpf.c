#include "fd_events.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct PendingCall {
    __u32 source;
    __u64 fd_ptr;
    __u64 cmd;
    __u64 fd_end;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct PendingCall);
} pending_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
} stacks SEC(".maps");

const volatile __u32 target_pid = 0;

struct SysEnterCtx {
    __u64 unused;
    long syscall_nr;
    __u64 args[6];
};

struct SysExitCtx {
    __u64 unused;
    long syscall_nr;
    long ret;
};

static __always_inline __u32 current_pid() {
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline __u32 current_tid() {
    return (__u32)bpf_get_current_pid_tgid();
}

static __always_inline int should_trace() {
    return target_pid == 0 || current_pid() == target_pid;
}

static __always_inline void remember_call(__u32 source, __u64 fd_ptr, __u64 cmd) {
    if (!should_trace()) {
        return;
    }
    __u32 tid = current_tid();
    struct PendingCall call = {};
    call.source = source;
    call.fd_ptr = fd_ptr;
    call.cmd = cmd;
    bpf_map_update_elem(&pending_calls, &tid, &call, BPF_ANY);
}

static __always_inline void remember_range(__u32 source, __u64 fd_begin, __u64 fd_end) {
    if (!should_trace()) {
        return;
    }
    __u32 tid = current_tid();
    struct PendingCall call = {};
    call.source = source;
    call.fd_ptr = fd_begin;
    call.fd_end = fd_end;
    bpf_map_update_elem(&pending_calls, &tid, &call, BPF_ANY);
}

static __always_inline void remember_source(__u32 source) {
    remember_call(source, 0, 0);
}

static __always_inline void emit_event(void* ctx, __u32 type, __u32 source, int fd) {
    if (!should_trace()) {
        return;
    }
    if ((type == FD_EVENT_OPEN || type == FD_EVENT_CLOSE) && fd < 0) {
        return;
    }

    struct FdEvent* event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = (__u32)(pid_tgid >> 32);
    event->tid = (__u32)pid_tgid;
    event->fd = fd;
    event->type = type;
    event->source = source;
    event->fd_end = 0;
    event->stack_id = type == FD_EVENT_OPEN
                          ? bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK)
                          : -1;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
}

static __always_inline void emit_range_event(void* ctx, __u32 source, __u32 fd_begin,
                                             __u32 fd_end) {
    if (!should_trace()) {
        return;
    }

    struct FdEvent* event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = (__u32)(pid_tgid >> 32);
    event->tid = (__u32)pid_tgid;
    event->fd = (int)fd_begin;
    event->type = FD_EVENT_CLOSE;
    event->source = source;
    event->fd_end = fd_end;
    event->stack_id = -1;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_enter_open(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_OPENAT);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_OPENAT);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_enter_openat2(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_OPENAT2);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_enter_socket(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_SOCKET);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_setup")
int trace_enter_io_uring_setup(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_IO_URING);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pipe")
int trace_enter_pipe(struct SysEnterCtx* ctx) {
    remember_call(FD_SOURCE_PIPE, ctx->args[0], 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pipe2")
int trace_enter_pipe2(struct SysEnterCtx* ctx) {
    remember_call(FD_SOURCE_PIPE, ctx->args[0], 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_eventfd")
int trace_enter_eventfd(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_EVENTFD);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_eventfd2")
int trace_enter_eventfd2(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_EVENTFD);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_create")
int trace_enter_timerfd_create(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_TIMERFD);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_signalfd")
int trace_enter_signalfd(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_SIGNALFD);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_signalfd4")
int trace_enter_signalfd4(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_SIGNALFD);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_enter_memfd_create(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_MEMFD);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup")
int trace_enter_dup(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_DUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_enter_dup2(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_DUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int trace_enter_dup3(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_DUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fcntl")
int trace_enter_fcntl(struct SysEnterCtx* ctx) {
    if (ctx->args[1] == 0 || ctx->args[1] == 1030) {
        remember_call(FD_SOURCE_FCNTL_DUP, 0, ctx->args[1]);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fcntl64")
int trace_enter_fcntl64(struct SysEnterCtx* ctx) {
    if (ctx->args[1] == 0 || ctx->args[1] == 1030) {
        remember_call(FD_SOURCE_FCNTL_DUP, 0, ctx->args[1]);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_enter_accept(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_ACCEPT4);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_enter_accept4(struct SysEnterCtx* ctx) {
    remember_source(FD_SOURCE_ACCEPT4);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int trace_exit_open(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit_openat(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_exit_openat2(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int trace_exit_socket(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_io_uring_setup")
int trace_exit_io_uring_setup(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int trace_exit_accept(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_exit_accept4(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pipe")
int trace_exit_pipe(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call && ctx->ret == 0) {
        int fds[2] = {};
        if (bpf_probe_read_user(&fds, sizeof(fds), (const void*)call->fd_ptr) == 0) {
            emit_event(ctx, FD_EVENT_OPEN, call->source, fds[0]);
            emit_event(ctx, FD_EVENT_OPEN, call->source, fds[1]);
        }
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pipe2")
int trace_exit_pipe2(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call && ctx->ret == 0) {
        int fds[2] = {};
        if (bpf_probe_read_user(&fds, sizeof(fds), (const void*)call->fd_ptr) == 0) {
            emit_event(ctx, FD_EVENT_OPEN, call->source, fds[0]);
            emit_event(ctx, FD_EVENT_OPEN, call->source, fds[1]);
        }
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_eventfd")
int trace_exit_eventfd(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_eventfd2")
int trace_exit_eventfd2(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_timerfd_create")
int trace_exit_timerfd_create(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_signalfd")
int trace_exit_signalfd(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_signalfd4")
int trace_exit_signalfd4(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_memfd_create")
int trace_exit_memfd_create(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup")
int trace_exit_dup(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup2")
int trace_exit_dup2(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup3")
int trace_exit_dup3(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fcntl")
int trace_exit_fcntl(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fcntl64")
int trace_exit_fcntl64(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        emit_event(ctx, FD_EVENT_OPEN, call->source, (int)ctx->ret);
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_enter_close(struct SysEnterCtx* ctx) {
    emit_event(ctx, FD_EVENT_CLOSE, FD_SOURCE_CLOSE, (int)ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close_range")
int trace_enter_close_range(struct SysEnterCtx* ctx) {
    remember_range(FD_SOURCE_CLOSE_RANGE, ctx->args[0], ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close_range")
int trace_exit_close_range(struct SysExitCtx* ctx) {
    __u32 tid = current_tid();
    struct PendingCall* call = bpf_map_lookup_elem(&pending_calls, &tid);
    if (call) {
        if (ctx->ret == 0) {
            emit_range_event(ctx, call->source, (__u32)call->fd_ptr, (__u32)call->fd_end);
        }
        bpf_map_delete_elem(&pending_calls, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_exit_execve(struct SysExitCtx* ctx) {
    if (ctx->ret == 0) {
        emit_event(ctx, FD_EVENT_EXEC, FD_SOURCE_EXEC, -1);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int trace_exit_execveat(struct SysExitCtx* ctx) {
    if (ctx->ret == 0) {
        emit_event(ctx, FD_EVENT_EXEC, FD_SOURCE_EXEC, -1);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void* ctx) {
    emit_event(ctx, FD_EVENT_EXIT, FD_SOURCE_EXIT, -1);
    return 0;
}
