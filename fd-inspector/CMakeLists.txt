# fd-inspector 是完全独立的 CMake 工程。在本目录 cmake -B build 即可构建。
cmake_minimum_required(VERSION 3.20)
project(fd_inspector LANGUAGES C CXX)

enable_testing()

add_library(fd_inspector_core
    src/fd_inspector.cpp
    src/fd_util.cpp
    src/leak_detector.cpp
    src/output.cpp
    src/proc_scan.cpp
    src/socket_diag.cpp
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBURING REQUIRED liburing)

target_include_directories(fd_inspector_core PUBLIC include)
target_include_directories(fd_inspector_core PRIVATE ${LIBURING_INCLUDE_DIRS})
target_link_directories(fd_inspector_core PRIVATE ${LIBURING_LIBRARY_DIRS})
target_link_libraries(fd_inspector_core PRIVATE ${LIBURING_LIBRARIES})
target_compile_features(fd_inspector_core PUBLIC cxx_std_17)

add_executable(fd-inspector src/main.cpp)
target_link_libraries(fd-inspector PRIVATE fd_inspector_core)

add_executable(fd_leak_demo demos/fd_leak.cpp)
target_compile_features(fd_leak_demo PRIVATE cxx_std_17)

add_executable(fd_sources_demo demos/fd_sources.cpp)
target_compile_features(fd_sources_demo PRIVATE cxx_std_17)

add_executable(fd_exec_demo demos/fd_exec.cpp)
target_compile_features(fd_exec_demo PRIVATE cxx_std_17)

add_executable(fd_socket_leak_demo demos/fd_socket_leak.cpp)
target_compile_features(fd_socket_leak_demo PRIVATE cxx_std_17)

add_executable(fd_anon_state_demo demos/fd_anon_state.cpp)
target_compile_features(fd_anon_state_demo PRIVATE cxx_std_17)

add_executable(fd_deleted_file_demo demos/fd_deleted_file.cpp)
target_compile_features(fd_deleted_file_demo PRIVATE cxx_std_17)

add_executable(fd_many_demo demos/fd_many.cpp)
target_compile_features(fd_many_demo PRIVATE cxx_std_17)

add_executable(fd_inspector_smoke tests/smoke.cpp)
target_link_libraries(fd_inspector_smoke PRIVATE fd_inspector_core)

find_program(BASH_EXECUTABLE bash REQUIRED)
add_test(NAME fd-inspector-smoke COMMAND fd_inspector_smoke)
add_test(NAME fd-inspector-help COMMAND fd-inspector --help)
add_test(NAME fd-inspector-invalid-max-fd
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --pid 1 --max-fd 999999999999999999999999 2>&1 | grep -q 'invalid value for --max-fd'"
        _ $<TARGET_FILE:fd-inspector>
)
add_test(NAME fd-inspector-interval-without-watch
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --pid 1 --leak-check 1 --interval-ms 10 2>&1 | grep -q -- '--interval-ms is only valid with --watch'"
        _ $<TARGET_FILE:fd-inspector>
)
add_test(NAME fd-inspector-max-fd-auto
    COMMAND ${BASH_EXECUTABLE} -c
        "$1 --pid $$ --max-fd 0 --json | grep -q '\"fd\":'"
        _ $<TARGET_FILE:fd-inspector>
)
add_test(NAME fd-inspector-demo-deleted-file
    COMMAND ${BASH_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/demo_regression.sh
        deleted-file
        $<TARGET_FILE_DIR:fd-inspector>
)
add_test(NAME fd-inspector-demo-anon-state
    COMMAND ${BASH_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/demo_regression.sh
        anon-state
        $<TARGET_FILE_DIR:fd-inspector>
)
add_test(NAME fd-inspector-demo-many-io-uring
    COMMAND ${BASH_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/demo_regression.sh
        many-io-uring
        $<TARGET_FILE_DIR:fd-inspector>
)
add_test(NAME fd-inspector-demo-socket-leak
    COMMAND ${BASH_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/demo_regression.sh
        socket-leak
        $<TARGET_FILE_DIR:fd-inspector>
)

option(FD_INSPECTOR_ENABLE_EBPF "Build optional eBPF fd leak tracer" OFF)

if(FD_INSPECTOR_ENABLE_EBPF)
    find_program(CLANG_EXECUTABLE clang REQUIRED)
    find_program(LLVM_STRIP_EXECUTABLE llvm-strip REQUIRED)
    if(DEFINED ENV{PKG_CONFIG_PATH} AND NOT "$ENV{PKG_CONFIG_PATH}" STREQUAL "")
        set(ENV{PKG_CONFIG_PATH} "/usr/lib64/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    else()
        set(ENV{PKG_CONFIG_PATH} "/usr/lib64/pkgconfig")
    endif()
    pkg_check_modules(LIBBPF REQUIRED libbpf)
    find_library(LIBBPF_LIBRARY
        NAMES bpf
        PATHS /usr/lib64 /usr/lib/x86_64-linux-gnu
        NO_DEFAULT_PATH
        REQUIRED
    )

    set(FD_LEAK_TRACER_BPF_OBJECT
        ${CMAKE_CURRENT_BINARY_DIR}/fd_leak_tracer.bpf.o
    )

    add_custom_command(
        OUTPUT ${FD_LEAK_TRACER_BPF_OBJECT}
        COMMAND ${CLANG_EXECUTABLE}
            -O2 -g -target bpf
            -D__TARGET_ARCH_x86
            -D__BPF_TRACING__
            -I${CMAKE_CURRENT_SOURCE_DIR}/ebpf
            -I/usr/include/x86_64-linux-gnu
            -c ${CMAKE_CURRENT_SOURCE_DIR}/ebpf/fd_leak_tracer.bpf.c
            -o ${FD_LEAK_TRACER_BPF_OBJECT}
        COMMAND ${LLVM_STRIP_EXECUTABLE} -g ${FD_LEAK_TRACER_BPF_OBJECT}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/ebpf/fd_leak_tracer.bpf.c
            ${CMAKE_CURRENT_SOURCE_DIR}/ebpf/fd_events.h
        VERBATIM
    )

    add_custom_target(fd_leak_tracer_bpf ALL
        DEPENDS ${FD_LEAK_TRACER_BPF_OBJECT}
    )

    add_executable(fd-leak-tracer ebpf/fd_leak_tracer.cpp)
    target_include_directories(fd-leak-tracer PRIVATE
        include
        ebpf
        ${LIBBPF_INCLUDE_DIRS}
    )
    target_link_libraries(fd-leak-tracer PRIVATE ${LIBBPF_LIBRARY} elf z dl)
    target_link_directories(fd-leak-tracer PRIVATE ${LIBBPF_LIBRARY_DIRS})
    set_target_properties(fd-leak-tracer PROPERTIES
        BUILD_RPATH "${LIBBPF_LIBRARY_DIRS}"
    )
    target_compile_features(fd-leak-tracer PRIVATE cxx_std_17)
    add_dependencies(fd-leak-tracer fd_leak_tracer_bpf)

    add_test(NAME fd-leak-tracer-help COMMAND fd-leak-tracer --help)
    add_test(NAME fd-leak-tracer-sources-regression
        COMMAND ${BASH_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/ebpf_regression.sh
            sources
            $<TARGET_FILE_DIR:fd-inspector>
    )
endif()
