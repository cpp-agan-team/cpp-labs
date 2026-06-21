cmake_minimum_required(VERSION 3.20)
project(mini_strace LANGUAGES CXX)

enable_testing()
find_package(Threads REQUIRED)

add_library(mini_strace_warnings INTERFACE)
target_compile_options(mini_strace_warnings INTERFACE
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-Wall -Wextra -Wshadow>
)

add_library(mini_strace_core
    src/attach.cpp
    src/deny_explainer.cpp
    src/decode_file.cpp
    src/decode_memory.cpp
    src/decode_net.cpp
    src/decode_poll_epoll.cpp
    src/decode_process.cpp
    src/decode_seccomp.cpp
    src/decoder.cpp
    src/event_pipeline.cpp
    src/injection.cpp
    src/io_latency.cpp
    src/lifecycle.cpp
    src/memory_reader.cpp
    src/net_trace.cpp
    src/output.cpp
    src/process_trace.cpp
    src/seccomp.cpp
    src/state.cpp
    src/summary.cpp
    src/syscall_table.cpp
    src/trace_loop.cpp
    src/tracer.cpp
)

target_include_directories(mini_strace_core PUBLIC include)
target_include_directories(mini_strace_core PRIVATE src)
target_compile_features(mini_strace_core PUBLIC cxx_std_17)
target_compile_definitions(mini_strace_core PRIVATE _GNU_SOURCE)
target_link_libraries(mini_strace_core PRIVATE mini_strace_warnings)

add_executable(mini-strace src/main.cpp)
target_link_libraries(mini-strace PRIVATE mini_strace_core mini_strace_warnings)

add_executable(hello_syscalls_demo demos/hello_syscalls.cpp)
target_compile_features(hello_syscalls_demo PRIVATE cxx_std_17)
target_link_libraries(hello_syscalls_demo PRIVATE mini_strace_warnings)

add_executable(file_ops_demo demos/file_ops.cpp)
target_compile_features(file_ops_demo PRIVATE cxx_std_17)
target_link_libraries(file_ops_demo PRIVATE mini_strace_warnings)

add_executable(mmap_ops_demo demos/mmap_ops.cpp)
target_compile_features(mmap_ops_demo PRIVATE cxx_std_17)
target_link_libraries(mmap_ops_demo PRIVATE mini_strace_warnings)

add_executable(fork_tree_demo demos/fork_tree.cpp)
target_compile_features(fork_tree_demo PRIVATE cxx_std_17)
target_link_libraries(fork_tree_demo PRIVATE mini_strace_warnings)

add_executable(threaded_writes_demo demos/threaded_writes.cpp)
target_compile_features(threaded_writes_demo PRIVATE cxx_std_17)
target_link_libraries(threaded_writes_demo PRIVATE mini_strace_warnings Threads::Threads)

add_executable(attach_thread_on_input_demo demos/attach_thread_on_input.cpp)
target_compile_features(attach_thread_on_input_demo PRIVATE cxx_std_17)
target_link_libraries(attach_thread_on_input_demo PRIVATE mini_strace_warnings Threads::Threads)

add_executable(futex_wait_demo demos/futex_wait.cpp)
target_compile_features(futex_wait_demo PRIVATE cxx_std_17)
target_link_libraries(futex_wait_demo PRIVATE mini_strace_warnings)

add_executable(socket_lifecycle_demo demos/socket_lifecycle.cpp)
target_compile_features(socket_lifecycle_demo PRIVATE cxx_std_17)
target_link_libraries(socket_lifecycle_demo PRIVATE mini_strace_warnings)

add_executable(signal_delivery_demo demos/signal_delivery.cpp)
target_compile_features(signal_delivery_demo PRIVATE cxx_std_17)
target_link_libraries(signal_delivery_demo PRIVATE mini_strace_warnings)

add_executable(eintr_read_demo demos/eintr_read.cpp)
target_compile_features(eintr_read_demo PRIVATE cxx_std_17)
target_link_libraries(eintr_read_demo PRIVATE mini_strace_warnings)

add_executable(exit_status_demo demos/exit_status.cpp)
target_compile_features(exit_status_demo PRIVATE cxx_std_17)
target_link_libraries(exit_status_demo PRIVATE mini_strace_warnings)

add_executable(signaled_exit_demo demos/signaled_exit.cpp)
target_compile_features(signaled_exit_demo PRIVATE cxx_std_17)
target_link_libraries(signaled_exit_demo PRIVATE mini_strace_warnings)

add_executable(fd_state_edges_demo demos/fd_state_edges.cpp)
target_compile_features(fd_state_edges_demo PRIVATE cxx_std_17)
target_link_libraries(fd_state_edges_demo PRIVATE mini_strace_warnings)

add_executable(state_escape_demo demos/state_escape.cpp)
target_compile_features(state_escape_demo PRIVATE cxx_std_17)
target_link_libraries(state_escape_demo PRIVATE mini_strace_warnings)

add_executable(seccomp_errno_demo demos/seccomp_errno.cpp)
target_compile_features(seccomp_errno_demo PRIVATE cxx_std_17)
target_link_libraries(seccomp_errno_demo PRIVATE mini_strace_warnings)

add_executable(syscall_loop_demo demos/syscall_loop.cpp)
target_compile_features(syscall_loop_demo PRIVATE cxx_std_17)
target_link_libraries(syscall_loop_demo PRIVATE mini_strace_warnings)

add_executable(exec_cloexec_demo demos/exec_cloexec.cpp)
target_compile_features(exec_cloexec_demo PRIVATE cxx_std_17)
target_link_libraries(exec_cloexec_demo PRIVATE mini_strace_warnings)

add_executable(openat2_ops_demo demos/openat2_ops.cpp)
target_compile_features(openat2_ops_demo PRIVATE cxx_std_17)
target_link_libraries(openat2_ops_demo PRIVATE mini_strace_warnings)

add_executable(epoll_ops_demo demos/epoll_ops.cpp)
target_compile_features(epoll_ops_demo PRIVATE cxx_std_17)
target_link_libraries(epoll_ops_demo PRIVATE mini_strace_warnings)

add_executable(poll_ops_demo demos/poll_ops.cpp)
target_compile_features(poll_ops_demo PRIVATE cxx_std_17)
target_compile_definitions(poll_ops_demo PRIVATE _GNU_SOURCE)
target_link_libraries(poll_ops_demo PRIVATE mini_strace_warnings)

add_executable(io_latency_demo demos/io_latency.cpp)
target_compile_features(io_latency_demo PRIVATE cxx_std_17)
target_compile_definitions(io_latency_demo PRIVATE _GNU_SOURCE)
target_link_libraries(io_latency_demo PRIVATE mini_strace_warnings)

add_executable(network_trace_demo demos/network_trace.cpp)
target_compile_features(network_trace_demo PRIVATE cxx_std_17)
target_compile_definitions(network_trace_demo PRIVATE _GNU_SOURCE)
target_link_libraries(network_trace_demo PRIVATE mini_strace_warnings)

add_executable(process_resource_demo demos/process_resource.cpp)
target_compile_features(process_resource_demo PRIVATE cxx_std_17)
target_compile_definitions(process_resource_demo PRIVATE _GNU_SOURCE)
target_link_libraries(process_resource_demo PRIVATE mini_strace_warnings Threads::Threads)

add_executable(mini_strace_smoke tests/smoke.cpp)
target_link_libraries(mini_strace_smoke PRIVATE mini_strace_core mini_strace_warnings)

find_program(BASH_EXECUTABLE bash REQUIRED)

add_test(NAME mini-strace-smoke COMMAND mini_strace_smoke $<TARGET_FILE:hello_syscalls_demo>)
add_test(NAME mini-strace-help COMMAND mini-strace --help)
add_test(NAME mini-strace-filter-write
    COMMAND ${BASH_EXECUTABLE} -c
        "out=$($1 --filter write --output - $2 2>/dev/null); printf '%s' \"$out\" | grep -q 'write(' && ! printf '%s' \"$out\" | grep -q 'openat('"
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:hello_syscalls_demo>
)
add_test(NAME mini-strace-json-write
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --json --filter write --output - $2 2>/dev/null | grep -q '\"name\":\"write\"'"
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:hello_syscalls_demo>
)
add_test(NAME mini-strace-json-schema-smoke
    COMMAND ${BASH_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/json_schema_smoke.sh
        $<TARGET_FILE:mini-strace>
        $<TARGET_FILE:hello_syscalls_demo>
        $<TARGET_FILE:file_ops_demo>
        $<TARGET_FILE:signal_delivery_demo>
        $<TARGET_FILE:exit_status_demo>
        $<TARGET_FILE:signaled_exit_demo>
        $<TARGET_FILE:seccomp_errno_demo>
        ${CMAKE_CURRENT_SOURCE_DIR}/docs/json-schema.event.schema.json
)
add_test(NAME mini-strace-summary
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --summary --filter write --output - $2 2>/dev/null | grep -q 'syscall'"
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:hello_syscalls_demo>
)
add_test(NAME mini-strace-open-enoent
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --filter openat --output - $2 2>/dev/null | grep -q 'ENOENT'"
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:file_ops_demo>
)
add_test(NAME mini-strace-mmap-state
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --state --filter mmap --output - $2 2>/dev/null | grep -q 'mapping'"
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:mmap_ops_demo>
)
add_test(NAME mini-strace-seccomp-bpf-filter-write
    COMMAND ${BASH_EXECUTABLE} -c
        "out=$($1 --seccomp-bpf --filter write --output - $2 2>/dev/null); printf '%s' \"$out\" | grep -q 'write(' && ! printf '%s' \"$out\" | grep -q 'openat('"
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:hello_syscalls_demo>
)
add_test(NAME mini-strace-seccomp-context-json
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --seccomp-bpf --json --filter write --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q '"seccomp_context"' &&
printf '%s\n' "$out" | grep -q '"action":"SECCOMP_RET_TRACE"' &&
printf '%s\n' "$out" | grep -q '"ret_data":0'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:hello_syscalls_demo>
)
add_test(NAME mini-strace-inject-write-error
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --filter write --inject write:error=EIO --output - $2 2>/dev/null | grep -q 'injected EIO'"
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:hello_syscalls_demo>
)
add_test(NAME mini-strace-follow-fork-write-json
    COMMAND ${BASH_EXECUTABLE} -c
        "count=$($1 --follow-fork --json --filter write --output - $2 2>/dev/null | grep -c '\"name\":\"write\"'); test \"$count\" -eq 2"
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:fork_tree_demo>
)
add_test(NAME mini-strace-follow-clone-thread-json
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --follow-fork --json --filter write --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | awk '
/"type":"syscall"/ && /"name":"write"/ {
    pid = $0
    tid = $0
    sub(/^.*"pid":/, "", pid)
    sub(/,.*/, "", pid)
    sub(/^.*"tid":/, "", tid)
    sub(/,.*/, "", tid)
    if (pid != tid) {
        saw_thread = 1
    }
    ++writes
}
END {
    exit !(writes >= 2 && saw_thread)
}'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:threaded_writes_demo>
)
add_test(NAME mini-strace-futex-diagnose
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --diagnose --filter futex --output - $2 2>/dev/null | grep -q 'futex_waits: calls='"
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:futex_wait_demo>
)
add_test(NAME mini-strace-socket-lifecycle-state
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --state --filter connect,accept4 --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q 'connect(.*AF_INET 127\.0\.0\.1:' &&
printf '%s\n' "$out" | grep -q 'accept4(.*AF_INET 127\.0\.0\.1:' &&
printf '%s\n' "$out" | grep -q 'peer=AF_INET 127\.0\.0\.1:'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:socket_lifecycle_demo>
)
add_test(NAME mini-strace-signal-delivery-json
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --signals --json --output - $2 2>/dev/null | grep -q '\"type\":\"signal\".*\"name\":\"SIGUSR1\".*\"delivered\":true'"
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:signal_delivery_demo>
)
add_test(NAME mini-strace-eintr-diagnose
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --signals --diagnose --filter read --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q 'read(.*ERESTART' &&
printf '%s\n' "$out" | grep -q 'signal(SIGUSR1) delivered' &&
printf '%s\n' "$out" | grep -q 'interrupted_syscalls:' &&
printf '%s\n' "$out" | grep -q '1x read'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:eintr_read_demo>
)
add_test(NAME mini-strace-lifecycle-exit-json
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --lifecycle --json --output - "$2" 2>/dev/null)
rc=$?
test "$rc" -eq 7 &&
printf '%s\n' "$out" | grep -q '"type":"exit".*"status":7.*"primary":true'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:exit_status_demo>
)
add_test(NAME mini-strace-lifecycle-signaled-json
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --lifecycle --json --output - "$2" 2>/dev/null)
rc=$?
test "$rc" -eq 143 &&
printf '%s\n' "$out" | grep -q '"type":"signaled".*"name":"SIGTERM".*"primary":true'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:signaled_exit_demo>
)
add_test(NAME mini-strace-attach-missing-pid-hint
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
err=$("$1" --pid 99999999 --max-events 1 2>&1 >/dev/null)
rc=$?
test "$rc" -ne 0 &&
printf '%s\n' "$err" | grep -q 'PTRACE_SEIZE failed for pid 99999999' &&
printf '%s\n' "$err" | grep -q 'hint:' &&
printf '%s\n' "$err" | grep -q 'target process does not exist'
        ]=]
        _ $<TARGET_FILE:mini-strace>
)
add_test(NAME mini-strace-invalid-size-options
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
err=$("$1" --strings -1 --output - "$2" 2>&1 >/dev/null)
rc=$?
test "$rc" -ne 0 &&
printf '%s\n' "$err" | grep -q 'invalid value for --strings: -1' &&
err=$("$1" --filter write --inject write:error=EIO:when=-1 --output - "$2" 2>&1 >/dev/null)
rc=$?
test "$rc" -ne 0 &&
printf '%s\n' "$err" | grep -q 'invalid value for --inject when: -1'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:hello_syscalls_demo>
)
add_test(NAME mini-strace-fd-state-edges
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --state --filter pipe2,socketpair,fcntl,read,write --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q 'pipe2(\[' &&
printf '%s\n' "$out" | grep -q 'socketpair(AF_UNIX' &&
printf '%s\n' "$out" | grep -q 'fcntl(.*F_DUPFD_CLOEXEC' &&
printf '%s\n' "$out" | grep -q 'kind=pipe' &&
printf '%s\n' "$out" | grep -q 'kind=socket' &&
printf '%s\n' "$out" | grep -q 'peer=fd:'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:fd_state_edges_demo>
)
add_test(NAME mini-strace-state-text-escape
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --state --filter write --output - "$2" 2>/dev/null)
test "$(printf '%s\n' "$out" | grep -c '^write(')" -eq 1 &&
printf '%s\n' "$out" | grep -q 'path=/tmp/mini-strace-state-escape-\\\\n-'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:state_escape_demo>
)
add_test(NAME mini-strace-seccomp-bpf-dump
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --seccomp-bpf --dump-seccomp --filter write --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q 'seccomp_filter(source=generated' &&
printf '%s\n' "$out" | grep -q 'SYS_write' &&
printf '%s\n' "$out" | grep -q 'SECCOMP_RET_TRACE' &&
printf '%s\n' "$out" | grep -q 'write('
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:hello_syscalls_demo>
)
add_test(NAME mini-strace-seccomp-errno-demo
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --dump-seccomp --filter getpid --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q 'getpid(' &&
printf '%s\n' "$out" | grep -q 'EPERM' &&
(printf '%s\n' "$out" | grep -q 'SECCOMP_RET_ERRNO(EPERM)' ||
 printf '%s\n' "$out" | grep -q 'seccomp_filter_unavailable')
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:seccomp_errno_demo>
)
add_test(NAME mini-strace-attach-live-clone-json
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
set -e
tmp=$(mktemp -d)
tracer_pid=
demo_pid=
cleanup() {
    rc=$?
    if [ -n "${tracer_pid:-}" ]; then
        kill "$tracer_pid" 2>/dev/null || true
    fi
    if [ -n "${demo_pid:-}" ]; then
        kill "$demo_pid" 2>/dev/null || true
    fi
    rm -rf "$tmp"
    exit "$rc"
}
trap cleanup EXIT

mkfifo "$tmp/in" "$tmp/out"
exec 3<> "$tmp/in"
exec 4<> "$tmp/out"
"$2" <&3 >&4 &
demo_pid=$!
IFS= read -r ready <&4
test "$ready" = ready

trace="$tmp/trace.jsonl"
err="$tmp/trace.err"
"$1" --pid "$demo_pid" --follow-fork --json --filter write --max-events 2 --output "$trace" 2>"$err" &
tracer_pid=$!

attached=0
for _ in $(seq 1 10000); do
    tracer=$(awk '/TracerPid:/ {print $2}' "/proc/$demo_pid/status" 2>/dev/null || printf '0')
    if [ "$tracer" != "0" ]; then
        attached=1
        break
    fi
done
test "$attached" -eq 1

printf x >&3
wait "$tracer_pid"
tracer_pid=
wait "$demo_pid"
demo_pid=

awk '
/"type":"syscall"/ && /"name":"write"/ {
    pid = $0
    tid = $0
    sub(/^.*"pid":/, "", pid)
    sub(/,.*/, "", pid)
    sub(/^.*"tid":/, "", tid)
    sub(/,.*/, "", tid)
    if (pid != tid) {
        saw_thread = 1
    }
    ++writes
}
END {
    exit !(writes >= 2 && saw_thread)
}' "$trace"
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:attach_thread_on_input_demo>
)
set_tests_properties(mini-strace-attach-live-clone-json PROPERTIES TIMEOUT 10)
add_test(NAME mini-strace-syscall-loop-getpid-decode
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --filter getpid --max-events 3 --output - "$2" --syscall getpid --count 3 2>/dev/null)
test "$(printf '%s\n' "$out" | grep -c 'getpid()')" -eq 3
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:syscall_loop_demo>
)
add_test(NAME mini-strace-seccomp-bpf-getpid-loop
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --seccomp-bpf --filter getpid --max-events 3 --output - "$2" --syscall getpid --count 3 2>/dev/null)
test "$(printf '%s\n' "$out" | grep -c 'getpid()')" -eq 3 &&
! printf '%s\n' "$out" | grep -q 'openat('
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:syscall_loop_demo>
)
add_test(NAME mini-strace-exec-cloexec-state
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --state --filter write --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q 'write(.*EBADF' &&
! printf '%s\n' "$out" | grep 'write(.*EBADF' | grep -q 'path=/dev/null'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:exec_cloexec_demo>
)
add_test(NAME mini-strace-execve-argv-decode
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --filter execve --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q 'execve(.*\[".*exec_cloexec_demo"' &&
printf '%s\n' "$out" | grep -q -- '"--after-exec"'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:exec_cloexec_demo>
)
add_test(NAME mini-strace-openat2-decode-state
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --state --filter openat2 --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q 'openat2(AT_FDCWD, "/dev/null", {flags=O_RDONLY|O_CLOEXEC' &&
printf '%s\n' "$out" | grep -q 'resolve=RESOLVE_NO_MAGICLINKS' &&
printf '%s\n' "$out" | grep -q 'cloexec=true'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:openat2_ops_demo>
)
add_test(NAME mini-strace-epoll-decode
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --filter epoll_create1,epoll_ctl,epoll_wait --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q 'epoll_create1(EPOLL_CLOEXEC)' &&
printf '%s\n' "$out" | grep -q 'epoll_ctl(.*EPOLL_CTL_ADD' &&
printf '%s\n' "$out" | grep -q 'events=EPOLLIN|EPOLLET' &&
printf '%s\n' "$out" | grep -q 'data_fd=' &&
printf '%s\n' "$out" | grep -q 'epoll_wait('
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:epoll_ops_demo>
)
add_test(NAME mini-strace-poll-decode
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --filter poll,ppoll --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q 'poll(\[' &&
printf '%s\n' "$out" | grep -q 'events=POLLIN|POLLERR' &&
printf '%s\n' "$out" | grep -q 'revents=POLLIN' &&
printf '%s\n' "$out" | grep -q 'events=POLLOUT' &&
printf '%s\n' "$out" | grep -q 'ppoll(' &&
printf '%s\n' "$out" | grep -q '{tv_sec=0, tv_nsec=0}'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:poll_ops_demo>
)
add_test(NAME mini-strace-io-latency-summary
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --io-latency --slow-us 0 --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q 'io_latency:' &&
printf '%s\n' "$out" | grep -q 'by_syscall:' &&
printf '%s\n' "$out" | grep -q 'fsync:' &&
printf '%s\n' "$out" | grep -q 'write:' &&
printf '%s\n' "$out" | grep -q 'poll:'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:io_latency_demo>
)
add_test(NAME mini-strace-basic-metadata-decode
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --json --filter fsync --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q '"name":"fsync"' &&
printf '%s\n' "$out" | grep -q '"args":\[{"name":"fd","value":"[0-9]'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:io_latency_demo>
)
add_test(NAME mini-strace-network-trace
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --net --state --follow-fork --filter socket,setsockopt,bind,listen,connect,accept4,sendmsg,recvmsg,sendto,recvfrom --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q 'SO_REUSEADDR' &&
printf '%s\n' "$out" | grep -q 'AF_INET 127\.0\.0\.1:' &&
printf '%s\n' "$out" | grep -q 'connect(' &&
printf '%s\n' "$out" | grep -q 'accept4(' &&
printf '%s\n' "$out" | grep -q 'sendmsg(' &&
printf '%s\n' "$out" | grep -q 'recvmsg(' &&
printf '%s\n' "$out" | grep -q 'network:' &&
printf '%s\n' "$out" | grep -q 'sent=' &&
printf '%s\n' "$out" | grep -q 'recv='
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:network_trace_demo>
)

add_test(NAME mini-strace-explain-seccomp-deny
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --explain-deny --dump-seccomp --filter getpid --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q 'getpid(' &&
printf '%s\n' "$out" | grep -q 'EPERM' &&
printf '%s\n' "$out" | grep -q 'diagnosis=maybe_seccomp' &&
printf '%s\n' "$out" | grep -q 'seccomp_errno_may_not_emit_ptrace_event'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:seccomp_errno_demo>
)

add_test(NAME mini-strace-process-resource-decode
    COMMAND ${BASH_EXECUTABLE} -c
        [=[
out=$("$1" --process --follow-fork --filter statx,newfstatat,prlimit64,close_range,clone,fork,vfork,wait4 --output - "$2" 2>/dev/null)
printf '%s\n' "$out" | grep -q 'statx(AT_FDCWD' &&
printf '%s\n' "$out" | grep -q 'STATX_' &&
printf '%s\n' "$out" | grep -q 'newfstatat(AT_FDCWD' &&
printf '%s\n' "$out" | grep -q 'RLIMIT_NOFILE' &&
printf '%s\n' "$out" | grep -q 'close_range(' &&
printf '%s\n' "$out" | grep -q 'CLONE_' &&
printf '%s\n' "$out" | grep -q 'wait4(' &&
printf '%s\n' "$out" | grep -q 'WIFEXITED' &&
printf '%s\n' "$out" | grep -q 'process:' &&
printf '%s\n' "$out" | grep -q 'resources:'
        ]=]
        _ $<TARGET_FILE:mini-strace> $<TARGET_FILE:process_resource_demo>
)

set_tests_properties(
    mini-strace-smoke
    mini-strace-help
    mini-strace-filter-write
    mini-strace-summary
    mini-strace-open-enoent
    mini-strace-syscall-loop-getpid-decode
    mini-strace-basic-metadata-decode
    mini-strace-invalid-size-options
    PROPERTIES LABELS "core"
)
set_tests_properties(
    mini-strace-json-write
    mini-strace-json-schema-smoke
    mini-strace-follow-fork-write-json
    mini-strace-follow-clone-thread-json
    mini-strace-signal-delivery-json
    mini-strace-lifecycle-exit-json
    mini-strace-lifecycle-signaled-json
    mini-strace-attach-live-clone-json
    PROPERTIES LABELS "json"
)
set_tests_properties(
    mini-strace-mmap-state
    mini-strace-socket-lifecycle-state
    mini-strace-fd-state-edges
    mini-strace-state-text-escape
    mini-strace-exec-cloexec-state
    mini-strace-openat2-decode-state
    PROPERTIES LABELS "state"
)
set_tests_properties(
    mini-strace-seccomp-bpf-filter-write
    mini-strace-seccomp-context-json
    mini-strace-seccomp-bpf-dump
    mini-strace-seccomp-errno-demo
    mini-strace-seccomp-bpf-getpid-loop
    mini-strace-explain-seccomp-deny
    PROPERTIES LABELS "seccomp"
)
set_tests_properties(
    mini-strace-inject-write-error
    mini-strace-futex-diagnose
    mini-strace-eintr-diagnose
    mini-strace-io-latency-summary
    PROPERTIES LABELS "diagnostics"
)
set_tests_properties(
    mini-strace-attach-missing-pid-hint
    PROPERTIES LABELS "attach"
)
set_tests_properties(
    mini-strace-execve-argv-decode
    mini-strace-epoll-decode
    mini-strace-poll-decode
    PROPERTIES LABELS "decode"
)
set_tests_properties(
    mini-strace-network-trace
    PROPERTIES LABELS "network"
)
set_tests_properties(
    mini-strace-process-resource-decode
    PROPERTIES LABELS "process"
)
