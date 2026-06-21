cmake_minimum_required(VERSION 3.20)
project(mem_map_viewer LANGUAGES CXX)

enable_testing()

add_library(mmv_warnings INTERFACE)
target_compile_options(mmv_warnings INTERFACE
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-Wall -Wextra -Wshadow -Wconversion -Wsign-conversion>
    $<$<AND:$<CONFIG:Debug>,$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>>:-Werror>
)

add_library(mem_map_viewer_core
    src/clear_refs.cpp
    src/cgroup_observer.cpp
    src/correlate.cpp
    src/diff.cpp
    src/fd_resolver.cpp
    src/growth_detector.cpp
    src/json_parse.cpp
    src/limits.cpp
    src/numa.cpp
    src/output.cpp
    src/page_flags.cpp
    src/pagemap.cpp
    src/perf_sampler.cpp
    src/proc_seed.cpp
    src/reconcile.cpp
    src/residency.cpp
    src/tracer.cpp
    src/uffd_tracer.cpp
    src/util.cpp
    src/vma_model.cpp
)

target_include_directories(mem_map_viewer_core PUBLIC include)
target_include_directories(mem_map_viewer_core PRIVATE src)
target_compile_features(mem_map_viewer_core PUBLIC cxx_std_17)
target_link_libraries(mem_map_viewer_core PRIVATE mmv_warnings)

add_executable(mem-map-viewer src/main.cpp)
target_link_libraries(mem-map-viewer PRIVATE mem_map_viewer_core mmv_warnings)

add_executable(mmap_leak_demo demos/mmap_leak.cpp)
target_compile_features(mmap_leak_demo PRIVATE cxx_std_17)
target_link_libraries(mmap_leak_demo PRIVATE mmv_warnings)

add_executable(mprotect_flip_demo demos/mprotect_flip.cpp)
target_compile_features(mprotect_flip_demo PRIVATE cxx_std_17)
target_link_libraries(mprotect_flip_demo PRIVATE mmv_warnings)

add_executable(file_mapping_demo demos/file_mapping.cpp)
target_compile_features(file_mapping_demo PRIVATE cxx_std_17)
target_link_libraries(file_mapping_demo PRIVATE mmv_warnings)

add_executable(thread_stack_growth_demo demos/thread_stack_growth.cpp)
target_link_libraries(thread_stack_growth_demo PRIVATE pthread mmv_warnings)
target_compile_features(thread_stack_growth_demo PRIVATE cxx_std_17)

add_executable(lazy_touch_demo demos/lazy_touch.cpp)
target_compile_features(lazy_touch_demo PRIVATE cxx_std_17)
target_link_libraries(lazy_touch_demo PRIVATE mmv_warnings)

add_executable(tlb_thrash_demo demos/tlb_thrash.cpp)
target_compile_features(tlb_thrash_demo PRIVATE cxx_std_17)
target_link_libraries(tlb_thrash_demo PRIVATE mmv_warnings)

add_executable(cgroup_pressure_demo demos/cgroup_pressure.cpp)
target_compile_features(cgroup_pressure_demo PRIVATE cxx_std_17)
target_link_libraries(cgroup_pressure_demo PRIVATE mmv_warnings)

add_executable(mem_map_viewer_smoke tests/smoke.cpp)
target_include_directories(mem_map_viewer_smoke PRIVATE src)
target_link_libraries(mem_map_viewer_smoke PRIVATE mem_map_viewer_core mmv_warnings)

find_program(BASH_EXECUTABLE bash REQUIRED)

add_test(NAME mem-map-viewer-smoke COMMAND mem_map_viewer_smoke)
add_test(NAME mem-map-viewer-help COMMAND mem-map-viewer --help)
add_test(NAME mem-map-viewer-self-json
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --pid $$ --json | grep -q '\"provenance\"'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-self-summary
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --pid $$ --summary | grep -q 'KIND/SOURCE'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-self-residency
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --pid $$ --residency --json | grep -q '\"entries\"'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-self-pages
    COMMAND ${BASH_EXECUTABLE} -c
        "range=$(awk 'NR==1 { split($1, a, \"-\"); print \"0x\" a[1] \"+4096\"; exit }' /proc/$$/maps); $1 --pid $$ --pages --range \"$range\" --json | grep -q '\"total_pages\"'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-self-numa
    COMMAND ${BASH_EXECUTABLE} -c
        "range=$(awk 'NR==1 { split($1, a, \"-\"); print \"0x\" a[1] \"+4096\"; exit }' /proc/$$/maps); $1 --pid $$ --numa --range \"$range\" --json | grep -q '\"available\"'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-self-page-flags
    COMMAND ${BASH_EXECUTABLE} -c
        "range=$(awk 'NR==1 { split($1, a, \"-\"); print \"0x\" a[1] \"+4096\"; exit }' /proc/$$/maps); $1 --pid $$ --page-flags --range \"$range\" --json | grep -q '\"pfn_visible\"'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-clear-soft-dirty-self
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --pid $$ --clear-soft-dirty --json | grep -q '\"available\"'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-self-limits
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --pid $$ --limits --json | grep -q '\"address_space\"'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-self-reconcile
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --pid $$ --reconcile --json | grep -q '\"missing_regions\":0'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-cgroup-self
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --cgroup self --psi --oom-risk --json | grep -q '\"current_bytes\"'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-insights-self
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --pid $$ --insights --json | grep -q '\"insights\"'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-insights-limits
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --pid $$ --insights --limits --json | grep -q '\"insights\"'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-insights-cgroup
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --cgroup self --insights --json | grep -q '\"insights\"'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-growth-check-self
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --pid $$ --growth-check 2 --interval-ms 1 --json | grep -q '\"size_slope_bytes_per_sample\"'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-invalid-large-pid
    COMMAND ${BASH_EXECUTABLE} -c
        "out=$($1 --pid 999999999999999999999999 --json 2>&1 >/dev/null); status=$?; test $status -ne 0 && printf '%s' \"$out\" | grep -q 'invalid value for --pid'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-invalid-negative-u64
    COMMAND ${BASH_EXECUTABLE} -c
        "out=$($1 --uffd-demo --uffd-length -1 2>&1 >/dev/null); status=$?; test $status -ne 0 && printf '%s' \"$out\" | grep -q 'invalid value for --uffd-length'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-perf-degrades-or-samples
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --pid $$ --perf-sample --duration-ms 1 --json | grep -q '\"available\"'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-demo-tlb-thrash
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 16777216 1 | grep -q 'tlb_thrash_demo pid='"
        _ $<TARGET_FILE:tlb_thrash_demo>
)
add_test(NAME mem-map-viewer-demo-cgroup-pressure
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 8388608 1048576 1 | grep -q 'cgroup_pressure_demo pid='"
        _ $<TARGET_FILE:cgroup_pressure_demo>
)
add_test(NAME mem-map-viewer-uffd-demo-degrades-or-records
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --uffd-demo --uffd-length 12582912 --json | grep -q '\"available\"'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-uffd-wp-demo-degrades-or-records
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --uffd-demo --uffd-mode wp --uffd-length 12582912 --json | grep -q '\"available\"'"
        _ $<TARGET_FILE:mem-map-viewer>
)
add_test(NAME mem-map-viewer-trace-mmap-demo
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --trace $2 1048576 1 2 --events | grep -q 'mmap'"
        _ $<TARGET_FILE:mem-map-viewer> $<TARGET_FILE:mmap_leak_demo>
)
add_test(NAME mem-map-viewer-trace-mprotect-demo
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --trace $2 1 2 --events | grep -q 'mprotect'"
        _ $<TARGET_FILE:mem-map-viewer> $<TARGET_FILE:mprotect_flip_demo>
)
add_test(NAME mem-map-viewer-trace-separator
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --events --trace -- /bin/true --help >/dev/null"
        _ $<TARGET_FILE:mem-map-viewer>
)
