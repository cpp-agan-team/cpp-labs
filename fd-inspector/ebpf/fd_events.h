#pragma once

#ifdef __BPF_TRACING__
#include <linux/types.h>
typedef __u64 fd_u64;
typedef __u32 fd_u32;
typedef __s32 fd_s32;
#else
#include <stdint.h>
typedef uint64_t fd_u64;
typedef uint32_t fd_u32;
typedef int32_t fd_s32;
#endif

enum FdEventType : fd_u32 {
    FD_EVENT_OPEN = 1,
    FD_EVENT_CLOSE = 2,
    FD_EVENT_EXEC = 3,
    FD_EVENT_EXIT = 4,
};

enum FdSource : fd_u32 {
    FD_SOURCE_OPENAT = 1,
    FD_SOURCE_OPENAT2 = 2,
    FD_SOURCE_SOCKET = 3,
    FD_SOURCE_ACCEPT4 = 4,
    FD_SOURCE_CLOSE = 5,
    FD_SOURCE_PIPE = 6,
    FD_SOURCE_EVENTFD = 7,
    FD_SOURCE_TIMERFD = 8,
    FD_SOURCE_SIGNALFD = 9,
    FD_SOURCE_MEMFD = 10,
    FD_SOURCE_DUP = 11,
    FD_SOURCE_FCNTL_DUP = 12,
    FD_SOURCE_EXEC = 13,
    FD_SOURCE_EXIT = 14,
    FD_SOURCE_IO_URING = 15,
    FD_SOURCE_CLOSE_RANGE = 16,
};

struct FdEvent {
    fd_u64 timestamp_ns;
    fd_u32 pid;
    fd_u32 tid;
    fd_s32 fd;
    fd_u32 type;
    fd_u32 source;
    fd_u32 fd_end;
    fd_s32 stack_id;
    char comm[16];
};
