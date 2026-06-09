#include "fd_events.h"
#include "unique_fd.hpp"

#include <algorithm>
#include <array>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <cxxabi.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <gelf.h>
#include <iostream>
#include <libelf.h>
#include <linux/perf_event.h>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <signal.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

volatile sig_atomic_t g_stop = 0;

struct CliOptions {
    int pid = 0;
    int seconds = 10;
    std::string bpf_object;
    bool verbose = false;
    bool json = false;
    bool symbols = true;
    bool addr2line = true;
};

struct StackFrame {
    uint64_t ip = 0;
    std::string object;
    std::string symbol;
    std::string file;
    std::string line;
    uint64_t object_offset = 0;
};

struct MemoryMap {
    uint64_t begin = 0;
    uint64_t end = 0;
    uint64_t file_offset = 0;
    std::string path;
};

struct OpenFd {
    FdEvent event{};
    std::vector<StackFrame> stack;
    std::string target;
};

struct ElfSymbol {
    uint64_t address = 0;
    uint64_t size = 0;
    std::string name;
};

struct ElfSymbolTable {
    bool loaded = false;
    bool available = false;
    std::vector<ElfSymbol> symbols;
};

struct TraceState {
    std::map<std::pair<uint32_t, int32_t>, OpenFd> open_fds;
    std::map<uint32_t, std::vector<MemoryMap>> maps_by_pid;
    std::map<std::pair<std::string, uint64_t>, StackFrame> symbol_cache;
    std::map<std::string, ElfSymbolTable> elf_symbols;
    uint64_t events_seen = 0;
    uint64_t open_events = 0;
    uint64_t close_events = 0;
    uint64_t range_close_events = 0;
    uint64_t range_closed_fds = 0;
    uint64_t exec_events = 0;
    uint64_t exit_events = 0;
    uint64_t exec_closed_fds = 0;
    uint64_t exit_cleared_fds = 0;
    int stacks_fd = -1;
    bool verbose = false;
    bool symbols = true;
    bool addr2line = true;
};

void handle_signal(int) {
    g_stop = 1;
}

void print_usage(std::ostream& out) {
    out << "fd-leak-tracer --pid <pid> [--seconds <n>] [--bpf-object <path>] "
           "[--verbose] [--json] [--no-symbols] [--no-addr2line]\n";
}

int parse_int_arg(const char* value, const std::string& name) {
    char* end = nullptr;
    long parsed = std::strtol(value, &end, 10);
    if (!value[0] || (end && *end != '\0') || parsed < 0) {
        throw std::invalid_argument("invalid value for " + name);
    }
    return static_cast<int>(parsed);
}

CliOptions parse_args(int argc, char** argv) {
    CliOptions options;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--pid" && i + 1 < argc) {
            options.pid = parse_int_arg(argv[++i], "--pid");
        } else if (arg == "--seconds" && i + 1 < argc) {
            options.seconds = parse_int_arg(argv[++i], "--seconds");
        } else if (arg == "--bpf-object" && i + 1 < argc) {
            options.bpf_object = argv[++i];
        } else if (arg == "--verbose") {
            options.verbose = true;
        } else if (arg == "--json") {
            options.json = true;
        } else if (arg == "--no-symbols") {
            options.symbols = false;
        } else if (arg == "--no-addr2line") {
            options.addr2line = false;
        } else if (arg == "--help" || arg == "-h") {
            print_usage(std::cout);
            std::exit(0);
        } else {
            throw std::invalid_argument("unknown or incomplete argument: " + arg);
        }
    }
    if (options.pid <= 0) {
        throw std::invalid_argument("--pid is required");
    }
    if (options.seconds <= 0) {
        throw std::invalid_argument("--seconds must be positive");
    }
    if (options.bpf_object.empty()) {
        throw std::invalid_argument("--bpf-object is required");
    }
    if (options.json) {
        options.verbose = false;
    }
    if (!options.symbols) {
        options.addr2line = false;
    }
    return options;
}

std::string json_escape(const std::string& input) {
    std::ostringstream out;
    for (unsigned char c : input) {
        switch (c) {
            case '\\':
                out << "\\\\";
                break;
            case '"':
                out << "\\\"";
                break;
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex;
                    out.width(4);
                    out.fill('0');
                    out << static_cast<int>(c) << std::dec;
                    out.fill(' ');
                } else {
                    out << static_cast<char>(c);
                }
                break;
        }
    }
    return out.str();
}

std::optional<uint64_t> parse_hex_u64(const std::string& value) {
    if (value.empty()) {
        return std::nullopt;
    }
    errno = 0;
    char* end = nullptr;
    unsigned long long parsed = std::strtoull(value.c_str(), &end, 16);
    if (errno != 0 || end == value.c_str()) {
        return std::nullopt;
    }
    return static_cast<uint64_t>(parsed);
}

std::string trim(std::string value) {
    const char* whitespace = " \t\r\n";
    size_t begin = value.find_first_not_of(whitespace);
    if (begin == std::string::npos) {
        return {};
    }
    size_t end = value.find_last_not_of(whitespace);
    return value.substr(begin, end - begin + 1);
}

std::string strip_deleted_suffix(std::string path) {
    constexpr const char* kDeletedSuffix = " (deleted)";
    size_t suffix_len = std::strlen(kDeletedSuffix);
    if (path.size() >= suffix_len &&
        path.compare(path.size() - suffix_len, suffix_len, kDeletedSuffix) == 0) {
        path.resize(path.size() - suffix_len);
    }
    return path;
}

std::string demangle_symbol(const char* name) {
    if (!name || name[0] == '\0') {
        return {};
    }
    int status = 0;
    std::unique_ptr<char, decltype(&std::free)> demangled(
        abi::__cxa_demangle(name, nullptr, nullptr, &status), &std::free);
    if (status == 0 && demangled) {
        return demangled.get();
    }
    return name;
}

std::string shell_quote(const std::string& value) {
    std::string quoted = "'";
    for (char c : value) {
        if (c == '\'') {
            quoted += "'\\''";
        } else {
            quoted.push_back(c);
        }
    }
    quoted += "'";
    return quoted;
}

std::string read_command_output(const std::string& command) {
    std::string output;
    FILE* pipe = ::popen(command.c_str(), "r");
    if (!pipe) {
        return output;
    }
    std::array<char, 256> buffer{};
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }
    ::pclose(pipe);
    return output;
}

class ElfHandle {
public:
    ElfHandle() = default;

    explicit ElfHandle(const std::string& path) : fd_(::open(path.c_str(), O_RDONLY | O_CLOEXEC)) {
        if (!fd_) {
            return;
        }
        elf_ = ::elf_begin(fd_.get(), ELF_C_READ, nullptr);
    }

    ~ElfHandle() {
        if (elf_) {
            ::elf_end(elf_);
        }
    }

    ElfHandle(const ElfHandle&) = delete;
    ElfHandle& operator=(const ElfHandle&) = delete;

    Elf* get() const { return elf_; }
    explicit operator bool() const { return elf_ != nullptr; }

private:
    UniqueFd fd_;
    Elf* elf_ = nullptr;
};

void append_elf_symbols(Elf* elf, Elf_Scn* section, const GElf_Shdr& header,
                        ElfSymbolTable* table) {
    Elf_Data* data = ::elf_getdata(section, nullptr);
    if (!data || header.sh_entsize == 0) {
        return;
    }

    size_t count = header.sh_size / header.sh_entsize;
    for (size_t i = 0; i < count; ++i) {
        GElf_Sym sym{};
        if (::gelf_getsym(data, static_cast<int>(i), &sym) == nullptr) {
            continue;
        }
        if (GELF_ST_TYPE(sym.st_info) != STT_FUNC || sym.st_value == 0) {
            continue;
        }
        const char* name = ::elf_strptr(elf, header.sh_link, sym.st_name);
        std::string demangled = demangle_symbol(name);
        if (demangled.empty()) {
            continue;
        }
        table->symbols.push_back(ElfSymbol{sym.st_value, sym.st_size, std::move(demangled)});
    }
}

ElfSymbolTable load_elf_symbols(const std::string& path) {
    ElfSymbolTable table;
    table.loaded = true;
    if (path.empty() || path[0] != '/') {
        return table;
    }
    if (::elf_version(EV_CURRENT) == EV_NONE) {
        return table;
    }

    ElfHandle handle(path);
    if (!handle) {
        return table;
    }
    if (::elf_kind(handle.get()) != ELF_K_ELF) {
        return table;
    }

    Elf_Scn* section = nullptr;
    while ((section = ::elf_nextscn(handle.get(), section)) != nullptr) {
        GElf_Shdr header{};
        if (::gelf_getshdr(section, &header) == nullptr) {
            continue;
        }
        if (header.sh_type == SHT_SYMTAB || header.sh_type == SHT_DYNSYM) {
            append_elf_symbols(handle.get(), section, header, &table);
        }
    }

    std::sort(table.symbols.begin(), table.symbols.end(),
              [](const ElfSymbol& lhs, const ElfSymbol& rhs) {
                  if (lhs.address != rhs.address) {
                      return lhs.address < rhs.address;
                  }
                  return lhs.size > rhs.size;
              });
    table.symbols.erase(std::unique(table.symbols.begin(), table.symbols.end(),
                                    [](const ElfSymbol& lhs, const ElfSymbol& rhs) {
                                        return lhs.address == rhs.address && lhs.name == rhs.name;
                                    }),
                        table.symbols.end());
    table.available = !table.symbols.empty();
    return table;
}

const ElfSymbolTable& elf_symbols_for(const std::string& object, TraceState* state) {
    std::string path = strip_deleted_suffix(object);
    auto found = state->elf_symbols.find(path);
    if (found != state->elf_symbols.end()) {
        return found->second;
    }
    auto inserted = state->elf_symbols.emplace(path, load_elf_symbols(path));
    return inserted.first->second;
}

std::optional<std::string> resolve_elf_symbol_at(const ElfSymbolTable& table, uint64_t address) {
    if (!table.available) {
        return std::nullopt;
    }

    const ElfSymbol* nearest = nullptr;
    for (const ElfSymbol& symbol : table.symbols) {
        if (symbol.address > address) {
            break;
        }
        nearest = &symbol;
    }
    if (!nearest) {
        return std::nullopt;
    }
    if (nearest->size != 0 && address >= nearest->address + nearest->size) {
        return std::nullopt;
    }
    return nearest->name;
}

void decorate_with_elf_symbols(StackFrame* frame, TraceState* state) {
    if (frame->object.empty() || frame->object[0] != '/') {
        return;
    }

    const ElfSymbolTable& table = elf_symbols_for(frame->object, state);
    if (std::optional<std::string> symbol = resolve_elf_symbol_at(table, frame->object_offset)) {
        frame->symbol = *symbol;
        return;
    }
    if (std::optional<std::string> symbol = resolve_elf_symbol_at(table, frame->ip)) {
        frame->symbol = *symbol;
    }
}

std::string read_fd_target(uint32_t pid, int32_t fd) {
    std::ostringstream path;
    path << "/proc/" << pid << "/fd/" << fd;
    std::string buffer(4096, '\0');
    ssize_t n = ::readlink(path.str().c_str(), &buffer[0], buffer.size() - 1);
    if (n < 0) {
        return {};
    }
    buffer.resize(static_cast<size_t>(n));
    return buffer;
}

bool path_exists(const std::string& path) {
    return ::access(path.c_str(), F_OK) == 0;
}

std::string tracepoint_path(const std::string& section) {
    const std::string prefix = "tracepoint/";
    if (section.find(prefix) != 0) {
        return {};
    }
    std::string rest = section.substr(prefix.size());
    size_t slash = rest.find('/');
    if (slash == std::string::npos) {
        return {};
    }
    return "/sys/kernel/tracing/events/" + rest.substr(0, slash) + "/" + rest.substr(slash + 1) +
           "/id";
}

std::vector<MemoryMap> read_process_maps(uint32_t pid) {
    std::ostringstream path;
    path << "/proc/" << pid << "/maps";
    std::ifstream input(path.str());

    std::vector<MemoryMap> maps;
    std::string line;
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::string range;
        std::string perms;
        std::string offset;
        std::string dev;
        std::string inode;
        if (!(fields >> range >> perms >> offset >> dev >> inode)) {
            continue;
        }
        size_t dash = range.find('-');
        if (dash == std::string::npos) {
            continue;
        }
        std::optional<uint64_t> begin = parse_hex_u64(range.substr(0, dash));
        std::optional<uint64_t> end = parse_hex_u64(range.substr(dash + 1));
        std::optional<uint64_t> file_offset = parse_hex_u64(offset);
        if (!begin || !end || !file_offset) {
            continue;
        }

        std::string map_path;
        std::getline(fields, map_path);
        while (!map_path.empty() && (map_path.front() == ' ' || map_path.front() == '\t')) {
            map_path.erase(map_path.begin());
        }
        maps.push_back(MemoryMap{*begin, *end, *file_offset, map_path});
    }
    return maps;
}

const char* source_name(uint32_t source) {
    switch (source) {
        case FD_SOURCE_OPENAT:
            return "openat";
        case FD_SOURCE_OPENAT2:
            return "openat2";
        case FD_SOURCE_SOCKET:
            return "socket";
        case FD_SOURCE_ACCEPT4:
            return "accept";
        case FD_SOURCE_CLOSE:
            return "close";
        case FD_SOURCE_PIPE:
            return "pipe";
        case FD_SOURCE_EVENTFD:
            return "eventfd";
        case FD_SOURCE_TIMERFD:
            return "timerfd";
        case FD_SOURCE_SIGNALFD:
            return "signalfd";
        case FD_SOURCE_MEMFD:
            return "memfd";
        case FD_SOURCE_DUP:
            return "dup";
        case FD_SOURCE_FCNTL_DUP:
            return "fcntl_dup";
        case FD_SOURCE_EXEC:
            return "exec";
        case FD_SOURCE_EXIT:
            return "exit";
        case FD_SOURCE_IO_URING:
            return "io_uring";
        case FD_SOURCE_CLOSE_RANGE:
            return "close_range";
        default:
            return "unknown";
    }
}

const char* event_type_name(uint32_t type) {
    switch (type) {
        case FD_EVENT_OPEN:
            return "open";
        case FD_EVENT_CLOSE:
            return "close";
        case FD_EVENT_EXEC:
            return "exec";
        case FD_EVENT_EXIT:
            return "exit";
        default:
            return "unknown";
    }
}

std::set<int32_t> list_live_fds(uint32_t pid) {
    std::ostringstream path;
    path << "/proc/" << pid << "/fd";
    std::set<int32_t> fds;
    DIR* dir = ::opendir(path.str().c_str());
    if (!dir) {
        return fds;
    }
    while (dirent* entry = ::readdir(dir)) {
        char* end = nullptr;
        long parsed = std::strtol(entry->d_name, &end, 10);
        if (end != entry->d_name && *end == '\0' && parsed >= 0) {
            fds.insert(static_cast<int32_t>(parsed));
        }
    }
    ::closedir(dir);
    return fds;
}

size_t sync_after_exec(TraceState* state, uint32_t pid) {
    std::set<int32_t> live = list_live_fds(pid);
    size_t removed = 0;
    for (auto it = state->open_fds.begin(); it != state->open_fds.end();) {
        if (it->first.first == pid && live.count(it->first.second) == 0) {
            it = state->open_fds.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    state->maps_by_pid.erase(pid);
    return removed;
}

size_t clear_process_state(TraceState* state, uint32_t pid) {
    size_t removed = 0;
    for (auto it = state->open_fds.begin(); it != state->open_fds.end();) {
        if (it->first.first == pid) {
            it = state->open_fds.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    state->maps_by_pid.erase(pid);
    return removed;
}

size_t clear_fd_range(TraceState* state, uint32_t pid, int32_t fd_begin, uint32_t fd_end) {
    size_t removed = 0;
    for (auto it = state->open_fds.begin(); it != state->open_fds.end();) {
        int32_t fd = it->first.second;
        bool in_range = it->first.first == pid && fd >= fd_begin &&
                        (fd_end == UINT32_MAX || static_cast<uint32_t>(fd) <= fd_end);
        if (in_range) {
            it = state->open_fds.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

const MemoryMap* find_map(const std::vector<MemoryMap>& maps, uint64_t ip) {
    for (const MemoryMap& map : maps) {
        if (ip >= map.begin && ip < map.end) {
            return &map;
        }
    }
    return nullptr;
}

void decorate_with_addr2line(StackFrame* frame) {
    if (frame->object.empty() || frame->object[0] != '/') {
        return;
    }
    std::string object_path = strip_deleted_suffix(frame->object);
    if (::access(object_path.c_str(), R_OK) != 0) {
        return;
    }

    std::ostringstream offset;
    offset << "0x" << std::hex << frame->object_offset;
    std::string command = "addr2line -f -C -e " + shell_quote(object_path) + " " +
                          shell_quote(offset.str()) + " 2>/dev/null";
    std::istringstream lines(read_command_output(command));
    std::string symbol;
    std::string location;
    std::getline(lines, symbol);
    std::getline(lines, location);
    symbol = trim(symbol);
    location = trim(location);

    if (!symbol.empty() && symbol != "??") {
        frame->symbol = symbol;
    }
    if (!location.empty() && location != "??:0") {
        size_t colon = location.rfind(':');
        if (colon != std::string::npos) {
            frame->file = location.substr(0, colon);
            frame->line = location.substr(colon + 1);
        } else {
            frame->file = location;
        }
    }
}

StackFrame symbolize_ip(uint64_t ip, const std::vector<MemoryMap>& maps, TraceState* state,
                        bool enabled) {
    StackFrame frame;
    frame.ip = ip;
    if (!enabled) {
        return frame;
    }

    if (const MemoryMap* map = find_map(maps, ip)) {
        frame.object = map->path;
        frame.object_offset = ip - map->begin + map->file_offset;
        std::pair<std::string, uint64_t> key{frame.object, frame.object_offset};
        auto cached = state->symbol_cache.find(key);
        if (cached != state->symbol_cache.end()) {
            frame.symbol = cached->second.symbol;
            frame.file = cached->second.file;
            frame.line = cached->second.line;
        } else {
            decorate_with_elf_symbols(&frame, state);
            if (state->addr2line) {
                decorate_with_addr2line(&frame);
            }
            state->symbol_cache[key] = frame;
        }
    } else {
        Dl_info info{};
        if (::dladdr(reinterpret_cast<void*>(ip), &info) != 0) {
            if (info.dli_fname) {
                frame.object = info.dli_fname;
            }
            if (info.dli_sname) {
                frame.symbol = info.dli_sname;
            }
        }
    }
    return frame;
}

std::vector<StackFrame> read_stack(int stacks_fd, int32_t stack_id,
                                   const std::vector<MemoryMap>& maps, TraceState* state,
                                   bool symbols) {
    if (stacks_fd < 0 || stack_id < 0) {
        return {};
    }

    std::array<uint64_t, PERF_MAX_STACK_DEPTH> ips{};
    if (::bpf_map_lookup_elem(stacks_fd, &stack_id, ips.data()) != 0) {
        return {};
    }

    std::vector<StackFrame> frames;
    for (uint64_t ip : ips) {
        if (ip == 0) {
            break;
        }
        if (ip >= (1ULL << 48)) {
            continue;
        }
        frames.push_back(symbolize_ip(ip, maps, state, symbols));
    }
    return frames;
}

std::string format_stack(const std::vector<StackFrame>& frames) {
    std::ostringstream out;
    for (size_t i = 0; i < frames.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        out << "0x" << std::hex << frames[i].ip << std::dec;
        if (!frames[i].symbol.empty()) {
            out << "(" << frames[i].symbol << ")";
        } else if (!frames[i].object.empty()) {
            out << "(" << frames[i].object << "+0x" << std::hex << frames[i].object_offset
                << std::dec << ")";
        }
    }
    return out.str();
}

int handle_event(void* ctx, void* data, size_t size) {
    if (size < sizeof(FdEvent)) {
        return 0;
    }

    auto* state = static_cast<TraceState*>(ctx);
    const auto* event = static_cast<const FdEvent*>(data);
    std::pair<uint32_t, int32_t> key{event->pid, event->fd};
    ++state->events_seen;

    if (event->type == FD_EVENT_OPEN) {
        ++state->open_events;
        OpenFd open_fd;
        open_fd.event = *event;
        auto maps_it = state->maps_by_pid.find(event->pid);
        if (maps_it == state->maps_by_pid.end()) {
            maps_it = state->maps_by_pid.emplace(event->pid, read_process_maps(event->pid)).first;
        }
        open_fd.stack =
            read_stack(state->stacks_fd, event->stack_id, maps_it->second, state, state->symbols);
        open_fd.target = read_fd_target(event->pid, event->fd);
        state->open_fds[key] = std::move(open_fd);
    } else if (event->type == FD_EVENT_CLOSE) {
        ++state->close_events;
        if (event->source == FD_SOURCE_CLOSE_RANGE) {
            ++state->range_close_events;
            state->range_closed_fds += clear_fd_range(state, event->pid, event->fd, event->fd_end);
        } else {
            state->open_fds.erase(key);
        }
    } else if (event->type == FD_EVENT_EXEC) {
        ++state->exec_events;
        state->exec_closed_fds += sync_after_exec(state, event->pid);
    } else if (event->type == FD_EVENT_EXIT) {
        ++state->exit_events;
        state->exit_cleared_fds += clear_process_state(state, event->pid);
    }

    if (state->verbose) {
        std::cout << event_type_name(event->type) << ' ' << "pid=" << event->pid
                  << " fd=" << event->fd << " source=" << source_name(event->source)
                  << " comm=" << event->comm;
        if (event->source == FD_SOURCE_CLOSE_RANGE) {
            std::cout << " fd_end=" << event->fd_end
                      << " range_closed_fds=" << state->range_closed_fds;
        }
        if (event->type == FD_EVENT_EXEC) {
            std::cout << " exec_closed_fds=" << state->exec_closed_fds;
        } else if (event->type == FD_EVENT_EXIT) {
            std::cout << " exit_cleared_fds=" << state->exit_cleared_fds;
        }
        std::cout << '\n';
    }
    return 0;
}

class BpfObject {
public:
    explicit BpfObject(bpf_object* object) : object_(object) {}
    ~BpfObject() {
        if (object_) {
            bpf_object__close(object_);
        }
    }

    BpfObject(const BpfObject&) = delete;
    BpfObject& operator=(const BpfObject&) = delete;

    bpf_object* get() const { return object_; }

private:
    bpf_object* object_ = nullptr;
};

class BpfLink {
public:
    explicit BpfLink(bpf_link* link = nullptr) : link_(link) {}
    ~BpfLink() {
        if (link_) {
            bpf_link__destroy(link_);
        }
    }

    BpfLink(const BpfLink&) = delete;
    BpfLink& operator=(const BpfLink&) = delete;

    BpfLink(BpfLink&& other) noexcept : link_(other.release()) {}

    BpfLink& operator=(BpfLink&& other) noexcept {
        if (this != &other) {
            if (link_) {
                bpf_link__destroy(link_);
            }
            link_ = other.release();
        }
        return *this;
    }

    explicit operator bool() const { return link_ != nullptr; }

private:
    bpf_link* release() {
        bpf_link* link = link_;
        link_ = nullptr;
        return link;
    }

    bpf_link* link_ = nullptr;
};

class RingBuffer {
public:
    explicit RingBuffer(ring_buffer* ring = nullptr) : ring_(ring) {}
    ~RingBuffer() {
        if (ring_) {
            ring_buffer__free(ring_);
        }
    }

    RingBuffer(const RingBuffer&) = delete;
    RingBuffer& operator=(const RingBuffer&) = delete;

    ring_buffer* get() const { return ring_; }
    explicit operator bool() const { return ring_ != nullptr; }

private:
    ring_buffer* ring_ = nullptr;
};

void set_target_pid(bpf_object* object, uint32_t pid) {
    bpf_map* rodata = bpf_object__find_map_by_name(object, "fd_leak_.rodata");
    if (!rodata) {
        rodata = bpf_object__find_map_by_name(object, ".rodata");
    }
    if (!rodata) {
        throw std::runtime_error("cannot find BPF rodata map");
    }
    if (bpf_map__set_initial_value(rodata, &pid, sizeof(pid)) != 0) {
        throw std::runtime_error("cannot set target_pid");
    }
}

void disable_missing_tracepoints(bpf_object* object) {
    bpf_program* program = nullptr;
    bpf_object__for_each_program(program, object) {
        const char* section = bpf_program__section_name(program);
        if (!section) {
            continue;
        }
        std::string event_id = tracepoint_path(section);
        if (!event_id.empty() && !path_exists(event_id)) {
            bpf_program__set_autoload(program, false);
        }
    }
}

std::vector<BpfLink> attach_programs(bpf_object* object) {
    std::vector<BpfLink> links;
    std::vector<std::string> skipped;
    bpf_program* program = nullptr;
    bpf_object__for_each_program(program, object) {
        if (bpf_program__fd(program) < 0) {
            continue;
        }
        bpf_link* link = bpf_program__attach(program);
        if (!link) {
            skipped.push_back(bpf_program__name(program));
            continue;
        }
        links.emplace_back(link);
    }
    if (links.empty()) {
        std::ostringstream message;
        message << "no BPF programs attached";
        if (!skipped.empty()) {
            message << "; first skipped=" << skipped.front();
        }
        throw std::runtime_error(message.str());
    }
    return links;
}

void print_text_report(const TraceState& state) {
    std::cout << "open_fds=" << state.open_fds.size() << " events=" << state.events_seen
              << " opens=" << state.open_events << " closes=" << state.close_events
              << " range_closes=" << state.range_close_events
              << " range_closed_fds=" << state.range_closed_fds << " execs=" << state.exec_events
              << " exits=" << state.exit_events << " exec_closed_fds=" << state.exec_closed_fds
              << " exit_cleared_fds=" << state.exit_cleared_fds << '\n';
    for (const auto& item : state.open_fds) {
        const OpenFd& open_fd = item.second;
        const FdEvent& event = open_fd.event;
        std::cout << "pid=" << event.pid << " fd=" << event.fd
                  << " source=" << source_name(event.source) << " comm=" << event.comm
                  << " stack_id=" << event.stack_id;
        if (!open_fd.target.empty()) {
            std::cout << " target=" << open_fd.target;
        }
        std::string stack = format_stack(open_fd.stack);
        if (!stack.empty()) {
            std::cout << " user_stack=" << stack;
        }
        std::cout << '\n';
    }
}

void print_stack_json(std::ostream& out, const std::vector<StackFrame>& frames) {
    out << "[";
    for (size_t i = 0; i < frames.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        out << "{";
        out << "\"ip\":\"0x" << std::hex << frames[i].ip << std::dec << "\"";
        out << ",\"object_offset\":\"0x" << std::hex << frames[i].object_offset << std::dec << "\"";
        out << ",\"object\":\"" << json_escape(frames[i].object) << "\"";
        out << ",\"symbol\":\"" << json_escape(frames[i].symbol) << "\"";
        out << ",\"file\":\"" << json_escape(frames[i].file) << "\"";
        out << ",\"line\":\"" << json_escape(frames[i].line) << "\"";
        out << "}";
    }
    out << "]";
}

void print_json_report(const TraceState& state) {
    std::cout << "{";
    std::cout << "\"open_fds\":" << state.open_fds.size();
    std::cout << ",\"stats\":{";
    std::cout << "\"events\":" << state.events_seen;
    std::cout << ",\"opens\":" << state.open_events;
    std::cout << ",\"closes\":" << state.close_events;
    std::cout << ",\"range_closes\":" << state.range_close_events;
    std::cout << ",\"range_closed_fds\":" << state.range_closed_fds;
    std::cout << ",\"execs\":" << state.exec_events;
    std::cout << ",\"exits\":" << state.exit_events;
    std::cout << ",\"exec_closed_fds\":" << state.exec_closed_fds;
    std::cout << ",\"exit_cleared_fds\":" << state.exit_cleared_fds;
    std::cout << "}";
    std::cout << ",\"fds\":[";
    bool first = true;
    for (const auto& item : state.open_fds) {
        if (!first) {
            std::cout << ",";
        }
        first = false;
        const OpenFd& open_fd = item.second;
        const FdEvent& event = open_fd.event;
        std::cout << "{";
        std::cout << "\"pid\":" << event.pid;
        std::cout << ",\"tid\":" << event.tid;
        std::cout << ",\"fd\":" << event.fd;
        std::cout << ",\"source\":\"" << source_name(event.source) << "\"";
        std::cout << ",\"comm\":\"" << json_escape(event.comm) << "\"";
        std::cout << ",\"target\":\"" << json_escape(open_fd.target) << "\"";
        std::cout << ",\"stack_id\":" << event.stack_id;
        std::cout << ",\"timestamp_ns\":" << event.timestamp_ns;
        std::cout << ",\"user_stack\":";
        print_stack_json(std::cout, open_fd.stack);
        std::cout << "}";
    }
    std::cout << "]}\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        CliOptions options = parse_args(argc, argv);
        libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

        bpf_object_open_opts open_opts{};
        open_opts.sz = sizeof(open_opts);
        BpfObject object(bpf_object__open_file(options.bpf_object.c_str(), &open_opts));
        if (!object.get()) {
            throw std::runtime_error("bpf_object__open_file failed");
        }

        set_target_pid(object.get(), static_cast<uint32_t>(options.pid));
        disable_missing_tracepoints(object.get());
        int err = bpf_object__load(object.get());
        if (err != 0) {
            throw std::runtime_error("bpf_object__load failed: " + std::to_string(err));
        }

        std::vector<BpfLink> links = attach_programs(object.get());
        bpf_map* events = bpf_object__find_map_by_name(object.get(), "events");
        bpf_map* stacks = bpf_object__find_map_by_name(object.get(), "stacks");
        if (!events || !stacks) {
            throw std::runtime_error("required BPF maps not found");
        }

        TraceState state;
        state.stacks_fd = bpf_map__fd(stacks);
        state.verbose = options.verbose;
        state.symbols = options.symbols;
        state.addr2line = options.addr2line;
        RingBuffer ring(ring_buffer__new(bpf_map__fd(events), handle_event, &state, nullptr));
        if (!ring) {
            throw std::runtime_error("ring_buffer__new failed");
        }

        ::signal(SIGINT, handle_signal);
        ::signal(SIGTERM, handle_signal);
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(options.seconds);
        while (!g_stop && std::chrono::steady_clock::now() < deadline) {
            int poll_result = ring_buffer__poll(ring.get(), 250);
            if (poll_result < 0 && poll_result != -EINTR) {
                throw std::runtime_error("ring_buffer__poll failed: " +
                                         std::to_string(poll_result));
            }
        }

        if (options.json) {
            print_json_report(state);
        } else {
            print_text_report(state);
        }
        return state.open_fds.empty() ? 0 : 2;
    } catch (const std::exception& ex) {
        std::cerr << "fd-leak-tracer: " << ex.what() << '\n';
        print_usage(std::cerr);
        return 1;
    }
}
