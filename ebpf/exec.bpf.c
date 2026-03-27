#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} exec_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} exec_drop_stats SEC(".maps");

/* increment_exec_drops records ring buffer reserve failures for the exec probe. */
static __always_inline void increment_exec_drops(void)
{
    __u32 key = 0;
    __u64 *value;

    value = bpf_map_lookup_elem(&exec_drop_stats, &key);
    if (!value) {
        return;
    }

    __sync_fetch_and_add(value, 1);
}

/* trace_sched_process_exec emits process execution events with parent PID context. */
SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct exec_event *event;
    struct task_struct *task;

    event = bpf_ringbuf_reserve(&exec_events, sizeof(*event), 0);
    if (!event) {
        increment_exec_drops();
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
