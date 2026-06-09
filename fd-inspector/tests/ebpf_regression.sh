#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <case> <bin-dir>" >&2
    exit 2
fi

case_name="$1"
bin_dir="$2"

tracer="$bin_dir/fd-leak-tracer"
bpf_object="$bin_dir/fd_leak_tracer.bpf.o"
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

require_file() {
    local path="$1"
    if [[ ! -e "${path}" ]]; then
        echo "missing required file: ${path}" >&2
        exit 2
    fi
}

wait_for_output() {
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

require_file "${tracer}"
require_file "${bpf_object}"
command -v jq >/dev/null

case "${case_name}" in
    sources)
        "${demo_dir}/fd_sources_demo" >"${tmp_dir}/demo.out" 2>"${tmp_dir}/demo.err" &
        demo_pid="$!"
        wait_for_output "fd_sources_demo pid="

        set +e
        "${tracer}" --pid "${demo_pid}" --seconds 5 --bpf-object "${bpf_object}" \
            --json --no-addr2line >"${tmp_dir}/trace.json" 2>"${tmp_dir}/trace.err"
        status=$?
        set -e
        if [[ "${status}" -ne 0 && "${status}" -ne 2 ]]; then
            cat "${tmp_dir}/trace.err" >&2 || true
            exit "${status}"
        fi

        jq -e '
            ([.fds[].source] | contains(["pipe", "eventfd", "dup", "timerfd", "signalfd", "memfd", "socket", "io_uring"])) and
            (.stats.range_closes >= 1) and
            (.stats.range_closed_fds >= 2)
        ' "${tmp_dir}/trace.json" >/dev/null
        ;;
    *)
        echo "unknown eBPF regression case: ${case_name}" >&2
        exit 2
        ;;
esac
