#include "internal.hpp"
#include "unique_fd.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <mutex>
#include <poll.h>
#include <stdexcept>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <thread>
#include <unistd.h>

#ifndef SYS_userfaultfd
#ifdef __NR_userfaultfd
#define SYS_userfaultfd __NR_userfaultfd
#endif
#endif

namespace mmv {
namespace {

uint64_t page_size() {
    long value = ::sysconf(_SC_PAGESIZE);
    if (value <= 0) {
        throw std::runtime_error("sysconf(_SC_PAGESIZE) failed");
    }
    return static_cast<uint64_t>(value);
}

uint64_t round_up(uint64_t value, uint64_t align) {
    if (value % align == 0) {
        return value;
    }
    return value + (align - (value % align));
}

struct LocalMapping {
    void* base = MAP_FAILED;
    size_t length = 0;

    LocalMapping() = default;
    ~LocalMapping() {
        if (base != MAP_FAILED) {
            ::munmap(base, length);
        }
    }

    LocalMapping(const LocalMapping&) = delete;
    LocalMapping& operator=(const LocalMapping&) = delete;
};

class UffdTracer {
public:
    UffdTracer(uint64_t page, std::string mode) : page_(page), mode_(std::move(mode)) {}

    ~UffdTracer() { stop(); }

    bool init(std::string* error) {
#ifdef SYS_userfaultfd
        stop_fd_.reset(::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
        if (!stop_fd_) {
            *error = std::string("eventfd failed: ") + std::strerror(errno);
            return false;
        }

        uffd_.reset(static_cast<int>(::syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK)));
        if (!uffd_) {
            *error = std::string("userfaultfd failed: ") + std::strerror(errno);
            return false;
        }

        uffdio_api api{};
        api.api = UFFD_API;
        if (mode_ == "wp") {
#ifdef UFFD_FEATURE_PAGEFAULT_FLAG_WP
            api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP;
#endif
        }
        if (::ioctl(uffd_.get(), UFFDIO_API, &api) != 0) {
            *error = std::string("UFFDIO_API failed: ") + std::strerror(errno);
            return false;
        }
        return true;
#else
        *error = "userfaultfd syscall is not available";
        return false;
#endif
    }

    bool register_range(uint64_t begin, uint64_t length, std::string* error) {
        begin_ = begin;
        uffdio_register reg{};
        reg.range.start = begin;
        reg.range.len = length;
        reg.mode = mode_ == "wp" ? UFFDIO_REGISTER_MODE_WP : UFFDIO_REGISTER_MODE_MISSING;
        if (::ioctl(uffd_.get(), UFFDIO_REGISTER, &reg) != 0) {
            *error = std::string("UFFDIO_REGISTER failed: ") + std::strerror(errno);
            return false;
        }
        return true;
    }

    bool writeprotect_range(uint64_t begin, uint64_t length, std::string* error) {
        uffdio_writeprotect wp{};
        wp.range.start = begin;
        wp.range.len = length;
        wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
        if (::ioctl(uffd_.get(), UFFDIO_WRITEPROTECT, &wp) != 0) {
            *error = std::string("UFFDIO_WRITEPROTECT failed: ") + std::strerror(errno);
            return false;
        }
        return true;
    }

    void start() {
        running_.store(true);
        handler_ = std::thread([this] { loop(); });
    }

    void stop() {
        running_.store(false);
        if (handler_.joinable()) {
            notify_stop();
            handler_.join();
        }
    }

    std::vector<UffdFaultEvent> events() const {
        std::lock_guard<std::mutex> guard(mu_);
        return events_;
    }

    std::string error() const {
        std::lock_guard<std::mutex> guard(mu_);
        return error_;
    }

private:
    void notify_stop() {
        if (!stop_fd_) {
            return;
        }
        uint64_t one = 1;
        ssize_t ignored = ::write(stop_fd_.get(), &one, sizeof(one));
        (void)ignored;
    }

    void set_error(const std::string& message) {
        std::lock_guard<std::mutex> guard(mu_);
        if (error_.empty()) {
            error_ = message;
        }
    }

    bool clear_writeprotect(uint64_t fault_addr) {
        for (int attempt = 0; attempt < 16 && running_.load(); ++attempt) {
            uffdio_writeprotect wp{};
            wp.range.start = fault_addr;
            wp.range.len = page_;
            wp.mode = 0;
            if (::ioctl(uffd_.get(), UFFDIO_WRITEPROTECT, &wp) == 0) {
                return true;
            }
            if (errno == EAGAIN) {
                std::this_thread::yield();
                continue;
            }
            set_error(std::string("UFFDIO_WRITEPROTECT wake failed: ") + std::strerror(errno));
            return false;
        }
        set_error("UFFDIO_WRITEPROTECT wake failed: retry limit reached");
        return false;
    }

    bool copy_missing_page(uint64_t fault_addr, const std::vector<unsigned char>& zero) {
        for (int attempt = 0; attempt < 16 && running_.load(); ++attempt) {
            uffdio_copy copy{};
            copy.dst = fault_addr;
            copy.src = reinterpret_cast<uint64_t>(zero.data());
            copy.len = page_;
            if (::ioctl(uffd_.get(), UFFDIO_COPY, &copy) == 0) {
                return true;
            }
            if (errno == EAGAIN) {
                std::this_thread::yield();
                continue;
            }
            set_error(std::string("UFFDIO_COPY failed: ") + std::strerror(errno));
            return false;
        }
        set_error("UFFDIO_COPY failed: retry limit reached");
        return false;
    }

    void loop() {
        std::vector<unsigned char> zero(static_cast<size_t>(page_), 0);
        while (running_.load()) {
            pollfd pfds[2]{};
            pfds[0].fd = uffd_.get();
            pfds[0].events = POLLIN;
            pfds[1].fd = stop_fd_.get();
            pfds[1].events = POLLIN;
            int ready = ::poll(pfds, 2, -1);
            if (ready < 0) {
                if (errno == EINTR) {
                    continue;
                }
                set_error(std::string("poll failed: ") + std::strerror(errno));
                break;
            }
            if ((pfds[1].revents & POLLIN) != 0) {
                break;
            }
            if ((pfds[0].revents & POLLIN) == 0) {
                continue;
            }

            uffd_msg msg{};
            ssize_t n = ::read(uffd_.get(), &msg, sizeof(msg));
            if (n != static_cast<ssize_t>(sizeof(msg)) || msg.event != UFFD_EVENT_PAGEFAULT) {
                continue;
            }

            const uint64_t fault_addr = msg.arg.pagefault.address & ~(page_ - 1);
            UffdFaultEvent event;
            event.address = fault_addr;
            event.offset = fault_addr >= begin_ ? fault_addr - begin_ : 0;
            event.timestamp_ns = detail::now_ns();
            event.write = (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE) != 0;
            event.wp = (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) != 0;
            {
                std::lock_guard<std::mutex> guard(mu_);
                events_.push_back(event);
            }

            const bool resolved =
                event.wp ? clear_writeprotect(fault_addr) : copy_missing_page(fault_addr, zero);
            if (!resolved) {
                running_.store(false);
                break;
            }
        }
    }

    uint64_t page_ = 0;
    uint64_t begin_ = 0;
    std::string mode_;
    UniqueFd uffd_;
    UniqueFd stop_fd_;
    std::atomic<bool> running_{false};
    std::thread handler_;
    mutable std::mutex mu_;
    std::vector<UffdFaultEvent> events_;
    std::string error_;
};

void touch_demo_pages(char* base, uint64_t length, uint64_t page) {
    const uint64_t second = std::min<uint64_t>(round_up(1024 * 1024, page), length - page);
    const uint64_t third = std::min<uint64_t>(round_up(2 * 1024 * 1024, page), length - page);
    base[0] = 1;
    base[second] = 2;
    volatile char value = base[third];
    (void)value;
}

void populate_pages(char* base, uint64_t length, uint64_t page) {
    for (uint64_t offset = 0; offset < length; offset += page) {
        base[offset] = 0;
    }
}

void writeprotect_demo_pages(char* base, uint64_t length, uint64_t page) {
    const uint64_t second = std::min<uint64_t>(round_up(1024 * 1024, page), length - page);
    const uint64_t third = std::min<uint64_t>(round_up(2 * 1024 * 1024, page), length - page);
    base[0] = 1;
    base[second] = 2;
    volatile char value = base[third];
    (void)value;
}

}  // namespace

UffdDemoResult run_uffd_demo(const std::string& mode, uint64_t length) {
    UffdDemoResult result;
    result.mode = mode;
    result.page_size = page_size();
    if (mode != "missing" && mode != "wp") {
        result.error = "uffd demo mode must be missing or wp";
        return result;
    }

    result.length = std::max<uint64_t>(round_up(length, result.page_size), result.page_size * 3);
    LocalMapping mapping;
    mapping.length = static_cast<size_t>(result.length);
    mapping.base =
        ::mmap(nullptr, mapping.length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping.base == MAP_FAILED) {
        result.error = std::string("mmap failed: ") + std::strerror(errno);
        return result;
    }
    result.base = reinterpret_cast<uint64_t>(mapping.base);

    if (mode == "wp") {
        populate_pages(static_cast<char*>(mapping.base), result.length, result.page_size);
    }

    UffdTracer tracer(result.page_size, mode);
    if (!tracer.init(&result.error)) {
        return result;
    }
    if (!tracer.register_range(result.base, result.length, &result.error)) {
        return result;
    }
    if (mode == "wp" && !tracer.writeprotect_range(result.base, result.length, &result.error)) {
        return result;
    }
    tracer.start();
    if (mode == "wp") {
        writeprotect_demo_pages(static_cast<char*>(mapping.base), result.length, result.page_size);
    } else {
        touch_demo_pages(static_cast<char*>(mapping.base), result.length, result.page_size);
    }

    const size_t expected_events = mode == "wp" ? 2 : 3;
    for (int i = 0; i < 50; ++i) {
        result.events = tracer.events();
        if (result.events.size() >= expected_events) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    tracer.stop();
    result.events = tracer.events();
    result.error = tracer.error();
    std::sort(result.events.begin(), result.events.end(),
              [](const UffdFaultEvent& lhs, const UffdFaultEvent& rhs) {
                  return lhs.timestamp_ns < rhs.timestamp_ns;
              });
    result.available = result.error.empty();
    return result;
}

}  // namespace mmv
