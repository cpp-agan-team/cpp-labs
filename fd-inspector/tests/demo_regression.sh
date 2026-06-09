#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <case> <bin-dir>" >&2
    exit 2
fi

case_name="$1"
bin_dir="$2"

inspector="$bin_dir/fd-inspector"
demo_dir="$bin_dir"

tmp_dir="$(mktemp -d)"
demo_pid=""

cleanup() {
    if [[ -n "${demo_pid}" ]] && kill -0 "${demo_pid}" 2>/dev/null; then
        kill "${demo_pid}" 2>/dev/null || true
        wait "${demo_pid}" 2>/dev/null || true
    fi
    rm -rf "${tmp_dir}"
}
trap cleanup EXIT

require_executable() {
    local path="$1"
    if [[ ! -x "${path}" ]]; then
        echo "missing executable: ${path}" >&2
        exit 2
    fi
}

start_demo() {
    local executable="$1"
    shift
    require_executable "${executable}"
    "${executable}" "$@" >"${tmp_dir}/demo.out" 2>"${tmp_dir}/demo.err" &
    demo_pid="$!"
}

wait_for_demo_output() {
    local pattern="$1"
    local deadline=$((SECONDS + 10))
    while (( SECONDS < deadline )); do
        if ! kill -0 "${demo_pid}" 2>/dev/null; then
            echo "demo exited before becoming ready" >&2
            cat "${tmp_dir}/demo.out" >&2 || true
            cat "${tmp_dir}/demo.err" >&2 || true
            exit 1
        fi
        if grep -q "${pattern}" "${tmp_dir}/demo.out" 2>/dev/null; then
            return 0
        fi
        sleep 0.05
    done

    echo "demo did not print ready pattern: ${pattern}" >&2
    cat "${tmp_dir}/demo.out" >&2 || true
    cat "${tmp_dir}/demo.err" >&2 || true
    exit 1
}

wait_for_inspector_match() {
    local jq_expr="$1"
    shift
    local deadline=$((SECONDS + 10))
    while (( SECONDS < deadline )); do
        if ! kill -0 "${demo_pid}" 2>/dev/null; then
            echo "demo exited while waiting for inspector match" >&2
            cat "${tmp_dir}/demo.out" >&2 || true
            cat "${tmp_dir}/demo.err" >&2 || true
            exit 1
        fi

        if "${inspector}" --pid "${demo_pid}" "$@" --json >"${tmp_dir}/inspect.json" 2>"${tmp_dir}/inspect.err" &&
           jq -e "${jq_expr}" "${tmp_dir}/inspect.json" >/dev/null; then
            return 0
        fi
        sleep 0.1
    done

    echo "inspector output did not satisfy jq expression: ${jq_expr}" >&2
    echo "--- demo.out ---" >&2
    cat "${tmp_dir}/demo.out" >&2 || true
    echo "--- demo.err ---" >&2
    cat "${tmp_dir}/demo.err" >&2 || true
    echo "--- inspect.json ---" >&2
    cat "${tmp_dir}/inspect.json" >&2 || true
    echo "--- inspect.err ---" >&2
    cat "${tmp_dir}/inspect.err" >&2 || true
    exit 1
}

require_executable "${inspector}"
command -v jq >/dev/null

case "${case_name}" in
    deleted-file)
        start_demo "${demo_dir}/fd_deleted_file_demo"
        wait_for_demo_output "held_deleted_file_size=8388608"
        wait_for_inspector_match \
            'map(select(.deleted == true and .size == 8388608)) | length == 1'
        ;;
    anon-state)
        start_demo "${demo_dir}/fd_anon_state_demo"
        wait_for_demo_output "fd_anon_state_demo pid="
        wait_for_inspector_match \
            'any(.[]; .type == "epoll" and ((.epoll_targets // []) | length) >= 1) and
             any(.[]; .type == "eventfd" and .eventfd_count == 7) and
             any(.[]; .type == "timerfd" and has("timerfd_ticks")) and
             any(.[]; .type == "signalfd" and has("signal_mask")) and
             any(.[]; .type == "inotify" and ((.inotify_watches // []) | length) == 1)'
        ;;
    many-io-uring)
        start_demo "${demo_dir}/fd_many_demo" 64
        wait_for_demo_output "held=64"
        wait_for_inspector_match \
            'length >= 64 and ((map(select(.target == "/dev/null")) | length) >= 64)' \
            --max-fd 0 --io-uring
        ;;
    socket-leak)
        start_demo "${demo_dir}/fd_socket_leak_demo"
        wait_for_demo_output "fd_socket_leak_demo pid="
        wait_for_inspector_match \
            'map(select(.type == "socket" and (.socket.state == "LISTEN" or .socket.state == "CLOSE_WAIT"))) | length >= 1' \
            --socket
        ;;
    *)
        echo "unknown demo regression case: ${case_name}" >&2
        exit 2
        ;;
esac
