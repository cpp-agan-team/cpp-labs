#pragma once

#include "internal.hpp"

#include <cstdint>
#include <iosfwd>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

namespace mini_strace {
namespace detail {

class EventMutator {
public:
    virtual ~EventMutator() = default;
    virtual void mutate(SyscallEvent& event) = 0;
};

class FinishingSink : public EventSink {
public:
    ~FinishingSink() override = default;
    virtual void finish(std::ostream& out) = 0;
};

class EventPipeline {
public:
    void add_mutator(std::unique_ptr<EventMutator> mutator);
    void add_finishing_sink(std::unique_ptr<FinishingSink> sink);
    void set_external_sink(EventSink* sink);
    void mutate(SyscallEvent& event);
    void observe(const SyscallEvent& event);
    void finish(std::ostream& out);

private:
    std::vector<std::unique_ptr<EventMutator>> mutators_;
    std::vector<std::unique_ptr<FinishingSink>> finishing_sinks_;
    EventSink* external_sink_ = nullptr;
};

struct TraceSession {
    std::set<pid_t> tasks;
    std::unordered_map<pid_t, ThreadState> threads;
    std::unordered_map<pid_t, pid_t> task_tgids;
    StateTracker state;
    EventPipeline pipeline;
    std::uint64_t sequence = 0;
    std::unordered_map<std::string, std::size_t> injection_seen;
    SeccompDumpState seccomp_dump;
    pid_t primary_pid = -1;
    TraceResult result;
};

enum class ResumeMode {
    Continue,
    Syscall,
};

std::runtime_error syscall_error(const std::string& what);
void resume_tracee(pid_t tid, ResumeMode mode, int signal);
void configure_event_pipeline(const TraceOptions& options, EventPipeline& pipeline,
                              EventSink* external_sink);
TraceResult event_loop(const TraceOptions& options, std::ostream& out, std::ostream& err,
                       TraceSession& session);

}  // namespace detail
}  // namespace mini_strace
