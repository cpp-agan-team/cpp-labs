#include "mini_strace.hpp"

#include <cassert>
#include <cstdint>
#include <sstream>
#include <string>

namespace {

class CountingSink : public mini_strace::EventSink {
public:
    void on_syscall(const mini_strace::SyscallEvent& event) override {
        ++count;
        last_name = event.name;
        last_ret = event.raw_ret;
        saw_decoded_args = !event.decoded_args.empty();
    }

    int count = 0;
    std::string last_name;
    std::int64_t last_ret = 0;
    bool saw_decoded_args = false;
};

}  // namespace

int main(int argc, char** argv) {
    std::uint64_t nr = 0;
    assert(mini_strace::syscall_number_by_name("write", nr));
    assert(mini_strace::syscall_name(nr) == "write");
    assert(mini_strace::errno_name(2) == "ENOENT");
    assert(!mini_strace::syscall_number_by_name("definitely_not_a_syscall", nr));
    if (argc > 1) {
        mini_strace::TraceOptions options;
        options.command = {argv[1]};
        options.filters.insert("write");
        options.max_events = 1;

        CountingSink sink;
        std::ostringstream err;
        (void)mini_strace::trace(options, sink, err);
        assert(sink.count == 1);
        assert(sink.last_name == "write");
        assert(sink.last_ret > 0);
        assert(sink.saw_decoded_args);
    }
    return 0;
}
