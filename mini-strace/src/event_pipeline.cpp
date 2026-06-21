#include "tracer_internal.hpp"

#include <memory>
#include <ostream>
#include <utility>

namespace mini_strace {
namespace detail {
namespace {

class SummarySink final : public FinishingSink {
public:
    SummarySink(bool write_summary, bool write_diagnostics)
        : write_summary_(write_summary), write_diagnostics_(write_diagnostics) {}

    void on_syscall(const SyscallEvent& event) override { summary_.observe(event); }

    void finish(std::ostream& out) override {
        if (write_summary_) {
            summary_.write(out);
        }
        if (write_diagnostics_) {
            summary_.write_diagnostics(out);
        }
    }

private:
    Summary summary_;
    bool write_summary_ = false;
    bool write_diagnostics_ = false;
};

class IoLatencySink final : public FinishingSink {
public:
    explicit IoLatencySink(std::uint64_t slow_threshold_us) : summary_(slow_threshold_us) {}

    void on_syscall(const SyscallEvent& event) override { summary_.observe(event); }

    void finish(std::ostream& out) override { summary_.write(out); }

private:
    IoLatencySummary summary_;
};

class NetworkSink final : public FinishingSink {
public:
    void on_syscall(const SyscallEvent& event) override { summary_.observe(event); }

    void finish(std::ostream& out) override { summary_.write(out); }

private:
    NetworkSummary summary_;
};

class ProcessSink final : public FinishingSink {
public:
    void on_syscall(const SyscallEvent& event) override { summary_.observe(event); }

    void finish(std::ostream& out) override { summary_.write(out); }

private:
    ProcessSummary summary_;
};

class DenyExplainMutator final : public EventMutator {
public:
    void mutate(SyscallEvent& event) override { event.diagnosis = explainer_.explain(event); }

private:
    DenyExplainer explainer_;
};

}  // namespace

void EventPipeline::add_mutator(std::unique_ptr<EventMutator> mutator) {
    if (mutator) {
        mutators_.push_back(std::move(mutator));
    }
}

void EventPipeline::add_finishing_sink(std::unique_ptr<FinishingSink> sink) {
    if (sink) {
        finishing_sinks_.push_back(std::move(sink));
    }
}

void EventPipeline::set_external_sink(EventSink* sink) {
    external_sink_ = sink;
}

void EventPipeline::mutate(SyscallEvent& event) {
    for (auto& mutator : mutators_) {
        mutator->mutate(event);
    }
}

void EventPipeline::observe(const SyscallEvent& event) {
    for (auto& sink : finishing_sinks_) {
        sink->on_syscall(event);
    }
    if (external_sink_ != nullptr) {
        external_sink_->on_syscall(event);
    }
}

void EventPipeline::finish(std::ostream& out) {
    for (auto& sink : finishing_sinks_) {
        sink->finish(out);
    }
}

void configure_event_pipeline(const TraceOptions& options, EventPipeline& pipeline,
                              EventSink* external_sink) {
    if (options.explain_deny) {
        pipeline.add_mutator(std::make_unique<DenyExplainMutator>());
    }
    if (options.summary || options.diagnose) {
        pipeline.add_finishing_sink(
            std::make_unique<SummarySink>(options.summary, options.diagnose));
    }
    if (options.io_latency) {
        pipeline.add_finishing_sink(std::make_unique<IoLatencySink>(options.slow_io_threshold_us));
    }
    if (options.net) {
        pipeline.add_finishing_sink(std::make_unique<NetworkSink>());
    }
    if (options.process) {
        pipeline.add_finishing_sink(std::make_unique<ProcessSink>());
    }
    pipeline.set_external_sink(external_sink);
}

}  // namespace detail
}  // namespace mini_strace
