#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

enum io_operation {
    IO_OP_READ = 1,
    IO_OP_WRITE = 2,
};

struct io_args {
    __u32 fd;
    __u32 count;
    __u64 buf;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct io_args);
    __uint(max_entries, 10240);
} inflight_reads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} io_events SEC(".maps");

/* fill_common_fields copies per-process metadata into an IO event. */
static __always_inline void fill_common_fields(struct sentinel_io_event *event, __u32 fd, __u8 op)
{
    __u64 id = bpf_get_current_pid_tgid();

    __builtin_memset(event, 0, sizeof(*event));
    event->pid = id >> 32;
    event->fd = fd;
    event->ts_ns = bpf_ktime_get_ns();
    event->op = op;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
}

/* submit_write_event captures the first bytes of a userspace write buffer. */
static __always_inline int submit_write_event(__u32 fd, const void *buf, __u32 count)
{
    struct sentinel_io_event *event;
    __u32 copy_len = count;

    if (!buf || count == 0) {
        return 0;
    }

    if (copy_len > HTTP_DATA_LEN) {
        copy_len = HTTP_DATA_LEN;
    }

    event = bpf_ringbuf_reserve(&io_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    fill_common_fields(event, fd, IO_OP_WRITE);
    if (bpf_probe_read_user(event->data, copy_len, buf) < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    event->data_len = copy_len;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* submit_read_event captures the first bytes returned from a read syscall. */
static __always_inline int submit_read_event(struct io_args *args, __s32 ret)
{
    struct sentinel_io_event *event;
    __u32 copy_len = ret;

    if (!args->buf || ret <= 0) {
        return 0;
    }

    if (copy_len > HTTP_DATA_LEN) {
        copy_len = HTTP_DATA_LEN;
    }

    event = bpf_ringbuf_reserve(&io_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    fill_common_fields(event, args->fd, IO_OP_READ);
    if (bpf_probe_read_user(event->data, copy_len, (const void *)args->buf) < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    event->data_len = copy_len;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* trace_write_enter captures request bytes as they are written by the process. */
SEC("kprobe/write_enter")
int trace_write_enter(struct pt_regs *ctx)
{
    __u32 fd = (__u32)PT_REGS_PARM1(ctx);
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    __u32 count = (__u32)PT_REGS_PARM3(ctx);

    return submit_write_event(fd, buf, count);
}

/* trace_sendto_enter captures request bytes written through socket send syscalls. */
SEC("kprobe/sendto_enter")
int trace_sendto_enter(struct pt_regs *ctx)
{
    __u32 fd = (__u32)PT_REGS_PARM1(ctx);
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    __u32 count = (__u32)PT_REGS_PARM3(ctx);

    return submit_write_event(fd, buf, count);
}

/* trace_read_enter stores read arguments so the return probe can fetch the response bytes. */
SEC("kprobe/read_enter")
int trace_read_enter(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct io_args args = {
        .fd = (__u32)PT_REGS_PARM1(ctx),
        .buf = (__u64)PT_REGS_PARM2(ctx),
        .count = (__u32)PT_REGS_PARM3(ctx),
    };

    bpf_map_update_elem(&inflight_reads, &id, &args, BPF_ANY);
    return 0;
}

/* trace_recvfrom_enter stores recvfrom arguments so the return probe can fetch response bytes. */
SEC("kprobe/recvfrom_enter")
int trace_recvfrom_enter(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct io_args args = {
        .fd = (__u32)PT_REGS_PARM1(ctx),
        .buf = (__u64)PT_REGS_PARM2(ctx),
        .count = (__u32)PT_REGS_PARM3(ctx),
    };

    bpf_map_update_elem(&inflight_reads, &id, &args, BPF_ANY);
    return 0;
}

/* trace_read_exit turns a successful read return into a captured response payload event. */
SEC("kretprobe/read_exit")
int BPF_KRETPROBE(trace_read_exit, int ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct io_args *args;

    args = bpf_map_lookup_elem(&inflight_reads, &id);
    if (!args) {
        return 0;
    }

    if (ret > 0) {
        submit_read_event(args, ret);
    }

    bpf_map_delete_elem(&inflight_reads, &id);
    return 0;
}

/* trace_recvfrom_exit turns a successful recvfrom return into a captured response payload event. */
SEC("kretprobe/recvfrom_exit")
int BPF_KRETPROBE(trace_recvfrom_exit, int ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct io_args *args;

    args = bpf_map_lookup_elem(&inflight_reads, &id);
    if (!args) {
        return 0;
    }

    if (ret > 0) {
        submit_read_event(args, ret);
    }

    bpf_map_delete_elem(&inflight_reads, &id);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
