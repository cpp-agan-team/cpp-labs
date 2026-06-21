#!/usr/bin/env bash
set -euo pipefail

mini_strace=$1
hello_demo=$2
file_demo=$3
signal_demo=$4
exit_demo=$5
signaled_demo=$6
seccomp_errno_demo=$7
schema_file=${8:-}

tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

require_pattern() {
    local file=$1
    local pattern=$2
    local label=$3
    if ! grep -Eq "${pattern}" "${file}"; then
        printf 'schema smoke failed: %s\n' "${label}" >&2
        sed -n '1,8p' "${file}" >&2
        exit 1
    fi
}

if [[ -n "${schema_file}" ]]; then
    require_pattern "${schema_file}" '"[$]schema": "https://json-schema.org/draft/2020-12/schema"' "schema draft"
    require_pattern "${schema_file}" '"oneOf": \[' "schema oneOf"
    require_pattern "${schema_file}" '"SyscallEvent": \{' "schema syscall event"
    require_pattern "${schema_file}" '"SignalEvent": \{' "schema signal event"
    require_pattern "${schema_file}" '"ExitEvent": \{' "schema exit event"
    require_pattern "${schema_file}" '"SignaledEvent": \{' "schema signaled event"
    require_pattern "${schema_file}" '"DecodedArg": \{' "schema decoded arg"
    require_pattern "${schema_file}" '"ErrorObject": \{' "schema error object"
    require_pattern "${schema_file}" '"SeccompContext": \{' "schema seccomp context"
    require_pattern "${schema_file}" '"Diagnosis": \{' "schema diagnosis"
fi

syscall_json="${tmp_dir}/syscall.jsonl"
"${mini_strace}" --json --filter write --output - "${hello_demo}" >"${syscall_json}" 2>/dev/null
require_pattern "${syscall_json}" '"type":"syscall"' "syscall type"
require_pattern "${syscall_json}" '"pid":[0-9]+' "syscall pid"
require_pattern "${syscall_json}" '"tid":[0-9]+' "syscall tid"
require_pattern "${syscall_json}" '"seq":[0-9]+' "syscall seq"
require_pattern "${syscall_json}" '"name":"write"' "syscall name"
require_pattern "${syscall_json}" '"nr":1' "syscall nr"
require_pattern "${syscall_json}" '"args":\[' "syscall args"
require_pattern "${syscall_json}" '"raw_args":\[' "syscall raw_args"
require_pattern "${syscall_json}" '"ret":[0-9]+' "syscall ret"
require_pattern "${syscall_json}" '"raw_ret":[0-9]+' "syscall raw_ret"
require_pattern "${syscall_json}" '"error":null' "syscall error null"
require_pattern "${syscall_json}" '"duration_ns":[0-9]+' "syscall duration"

error_json="${tmp_dir}/error.jsonl"
"${mini_strace}" --json --filter openat --output - "${file_demo}" >"${error_json}" 2>/dev/null
require_pattern "${error_json}" '"error":\{"name":"ENOENT","value":2,"message":"No such file or directory"\}' "error object"

seccomp_json="${tmp_dir}/seccomp.jsonl"
"${mini_strace}" --seccomp-bpf --json --filter write --output - "${hello_demo}" >"${seccomp_json}" 2>/dev/null
require_pattern "${seccomp_json}" '"seccomp_context":\{' "seccomp context"
require_pattern "${seccomp_json}" '"ptrace_event":true' "seccomp ptrace_event"
require_pattern "${seccomp_json}" '"action":"SECCOMP_RET_TRACE"' "seccomp action"
require_pattern "${seccomp_json}" '"ret_data":0' "seccomp ret_data"

diagnosis_json="${tmp_dir}/diagnosis.jsonl"
"${mini_strace}" --explain-deny --json --filter getpid --output - "${seccomp_errno_demo}" >"${diagnosis_json}" 2>/dev/null
require_pattern "${diagnosis_json}" '"diagnosis":\{' "diagnosis object"
require_pattern "${diagnosis_json}" '"category":"maybe_seccomp"' "diagnosis category"
require_pattern "${diagnosis_json}" '"confidence":"medium"' "diagnosis confidence"
require_pattern "${diagnosis_json}" '"evidence":\[' "diagnosis evidence"

signal_json="${tmp_dir}/signal.jsonl"
"${mini_strace}" --signals --json --output - "${signal_demo}" >"${signal_json}" 2>/dev/null
require_pattern "${signal_json}" '"type":"signal"' "signal type"
require_pattern "${signal_json}" '"signal":\{' "signal object"
require_pattern "${signal_json}" '"name":"SIGUSR1"' "signal name"
require_pattern "${signal_json}" '"number":[0-9]+' "signal number"
require_pattern "${signal_json}" '"delivered":true' "signal delivered"

exit_json="${tmp_dir}/exit.jsonl"
"${mini_strace}" --lifecycle --json --output - "${exit_demo}" >"${exit_json}" 2>/dev/null || true
require_pattern "${exit_json}" '"type":"exit"' "exit type"
require_pattern "${exit_json}" '"status":7' "exit status"
require_pattern "${exit_json}" '"primary":true' "exit primary"

signaled_json="${tmp_dir}/signaled.jsonl"
"${mini_strace}" --lifecycle --json --output - "${signaled_demo}" >"${signaled_json}" 2>/dev/null || true
require_pattern "${signaled_json}" '"type":"signaled"' "signaled type"
require_pattern "${signaled_json}" '"signal":\{' "signaled signal object"
require_pattern "${signaled_json}" '"name":"SIGTERM"' "signaled name"
require_pattern "${signaled_json}" '"number":15' "signaled number"
require_pattern "${signaled_json}" '"primary":true' "signaled primary"
