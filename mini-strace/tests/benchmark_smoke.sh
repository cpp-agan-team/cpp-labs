#!/usr/bin/env bash
set -u

usage() {
    cat <<'USAGE'
usage: tests/benchmark_smoke.sh [--format text|json|csv] [--json] [--csv] [build_dir] [count]

Runs a non-threshold benchmark smoke for mini-strace. Timings are intended for
same-machine comparisons only.
USAGE
}

format=text
positionals=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --format)
            if [[ $# -lt 2 ]]; then
                usage >&2
                exit 2
            fi
            format=$2
            shift 2
            ;;
        --json)
            format=json
            shift
            ;;
        --csv)
            format=csv
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            positionals+=("$1")
            shift
            ;;
    esac
done

case "${format}" in
    text|json|csv) ;;
    *)
        printf 'invalid format: %s\n' "${format}" >&2
        exit 2
        ;;
esac

build_dir=${positionals[0]:-build}
count=${positionals[1]:-1000}

if ! [[ "${count}" =~ ^[1-9][0-9]*$ ]]; then
    printf 'count must be a positive integer: %s\n' "${count}" >&2
    exit 2
fi

mini_strace="${build_dir}/mini-strace"
syscall_loop="${build_dir}/syscall_loop_demo"
io_demo="${build_dir}/io_latency_demo"
net_demo="${build_dir}/network_trace_demo"
process_demo="${build_dir}/process_resource_demo"

if [[ ! -x "${mini_strace}" ]]; then
    printf 'missing executable: %s\n' "${mini_strace}" >&2
    exit 1
fi

if [[ ! -x "${syscall_loop}" ]]; then
    printf 'missing executable: %s\n' "${syscall_loop}" >&2
    exit 1
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

json_escape() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    value=${value//$'\r'/\\r}
    value=${value//$'\t'/\\t}
    printf '%s' "${value}"
}

csv_escape() {
    local value=$1
    value=${value//\"/\"\"}
    printf '"%s"' "${value}"
}

command_text() {
    local text
    printf -v text '%q ' "$@"
    printf '%s' "${text% }"
}

count_events() {
    local file=$1
    grep -Ec '^[[]pid [0-9]+[]] [A-Za-z0-9_]+[(]|^[A-Za-z0-9_]+[(]' "${file}" || true
}

print_header() {
    case "${format}" in
        text)
            printf '# mini-strace benchmark smoke\n'
            printf 'build_dir: %s\n' "${build_dir}"
            printf 'count: %s\n' "${count}"
            printf 'note: wall time is environment dependent; compare runs on the same machine.\n'
            ;;
        json)
            printf '{"type":"meta","build_dir":"%s","count":%s,"note":"wall time is environment dependent; compare runs on the same machine"}\n' \
                "$(json_escape "${build_dir}")" "${count}"
            ;;
        csv)
            printf 'name,status,wall_ms,events,command\n'
            ;;
    esac
}

print_case() {
    local name=$1
    local status=$2
    local wall_ms=$3
    local events=$4
    local command=$5
    case "${format}" in
        text)
            printf 'status: %s\n' "${status}"
            printf 'wall_ms: %.3f\n' "${wall_ms}"
            printf 'events: %s\n' "${events}"
            ;;
        json)
            printf '{"type":"case","name":"%s","status":%s,"wall_ms":%.3f,"events":%s,"command":"%s"}\n' \
                "$(json_escape "${name}")" "${status}" "${wall_ms}" "${events}" \
                "$(json_escape "${command}")"
            ;;
        csv)
            csv_escape "${name}"
            printf ',%s,%.3f,%s,' "${status}" "${wall_ms}" "${events}"
            csv_escape "${command}"
            printf '\n'
            ;;
    esac
}

run_case() {
    local name=$1
    shift
    local output="${tmp_dir}/${name}.out"
    local args=()
    local start_ns
    local end_ns
    local rc
    local events
    local command
    local wall_ms

    for arg in "$@"; do
        if [[ "${arg}" == "@OUTPUT@" ]]; then
            args+=("--output" "${output}")
        else
            args+=("${arg}")
        fi
    done

    command=$(command_text "${args[@]}")
    if [[ "${format}" == "text" ]]; then
        printf '\n## %s\n' "${name}"
        printf 'command: %s\n' "${command}"
    fi

    start_ns=$(date +%s%N)
    "${args[@]}" >/dev/null 2>"${output}.err"
    rc=$?
    end_ns=$(date +%s%N)

    events=$(count_events "${output}")
    wall_ms="$((end_ns - start_ns))e-6"
    print_case "${name}" "${rc}" "${wall_ms}" "${events}" "${command}"
    if [[ ${rc} -ne 0 ]]; then
        sed -n '1,12p' "${output}.err" >&2
        return "${rc}"
    fi
}

print_header

run_case ptrace-getpid \
    "${mini_strace}" --filter getpid --max-events "${count}" @OUTPUT@ \
    "${syscall_loop}" --syscall getpid --count "${count}" || exit 1

run_case seccomp-getpid \
    "${mini_strace}" --seccomp-bpf --filter getpid --max-events "${count}" @OUTPUT@ \
    "${syscall_loop}" --syscall getpid --count "${count}" || exit 1

run_case decoded-write \
    "${mini_strace}" --filter write --max-events "${count}" @OUTPUT@ \
    "${syscall_loop}" --syscall write --count "${count}" || exit 1

run_case raw-write \
    "${mini_strace}" --raw --filter write --max-events "${count}" @OUTPUT@ \
    "${syscall_loop}" --syscall write --count "${count}" || exit 1

run_case summary-getpid \
    "${mini_strace}" --summary --filter getpid --max-events "${count}" @OUTPUT@ \
    "${syscall_loop}" --syscall getpid --count "${count}" || exit 1

if [[ -x "${io_demo}" ]]; then
    run_case io-latency "${mini_strace}" --io-latency --slow-us 0 @OUTPUT@ "${io_demo}" || exit 1
fi

if [[ -x "${net_demo}" ]]; then
    run_case network "${mini_strace}" --net @OUTPUT@ "${net_demo}" || exit 1
fi

if [[ -x "${process_demo}" ]]; then
    run_case process "${mini_strace}" --process @OUTPUT@ "${process_demo}" || exit 1
fi
