#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} exec_events SEC(".maps");

/* trace_sched_process_exec emits process execution events with parent PID context. */
SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct exec_event *event;
    struct task_struct *task;

    event = bpf_ringbuf_reserve(&exec_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    task = (struct task_struct *)bpf_get_current_task();
    event->pid = ctx->pid;
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
