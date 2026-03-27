#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} accept_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} accept_drop_stats SEC(".maps");

/* increment_accept_drops records ring buffer reserve failures for the accept probe. */
static __always_inline void increment_accept_drops(void)
{
    __u32 key = 0;
    __u64 *value;

    value = bpf_map_lookup_elem(&accept_drop_stats, &key);
    if (!value) {
        return;
    }

    __sync_fetch_and_add(value, 1);
}

/* fill_event_from_socket copies peer address details from a kernel socket into an event. */
static __always_inline void fill_event_from_socket(struct accept_event *event, struct sock *sock)
{
    __u16 family = BPF_CORE_READ(sock, __sk_common.skc_family);

    event->family = family;

    if (family == AF_INET) {
        __u32 daddr = BPF_CORE_READ(sock, __sk_common.skc_daddr);

        event->port = bpf_ntohs(BPF_CORE_READ(sock, __sk_common.skc_dport));
        __builtin_memcpy(event->addr, &daddr, sizeof(daddr));
        return;
    }

    if (family == AF_INET6) {
        event->port = bpf_ntohs(BPF_CORE_READ(sock, __sk_common.skc_dport));
        BPF_CORE_READ_INTO(event->addr, sock, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }
}

/* submit_unknown_event emits an accept event even when peer parsing fails. */
static __always_inline int submit_unknown_event(__s32 ret)
{
    struct accept_event *event;
    __u64 id = bpf_get_current_pid_tgid();

    event = bpf_ringbuf_reserve(&accept_events, sizeof(*event), 0);
    if (!event) {
        increment_accept_drops();
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->pid = id >> 32;
    event->fd = ret;
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* submit_socket_event emits an accept event by reading peer data from the accepted socket. */
static __always_inline int submit_socket_event(__s32 ret)
{
    struct task_struct *task;
    struct files_struct *files;
    struct fdtable *fdt;
    struct file **fd_entries;
    struct file *file = NULL;
    struct socket *socket;
    struct sock *sock;
    struct accept_event *event;
    __u64 id = bpf_get_current_pid_tgid();
    unsigned int max_fds;

    task = (struct task_struct *)bpf_get_current_task();
    files = BPF_CORE_READ(task, files);
    if (!files) {
        return submit_unknown_event(ret);
    }

    fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) {
        return submit_unknown_event(ret);
    }

    max_fds = BPF_CORE_READ(fdt, max_fds);
    if ((__u32)ret >= max_fds) {
        return submit_unknown_event(ret);
    }

    fd_entries = BPF_CORE_READ(fdt, fd);
    if (!fd_entries) {
        return submit_unknown_event(ret);
    }

    bpf_core_read(&file, sizeof(file), &fd_entries[ret]);
    if (!file) {
        return submit_unknown_event(ret);
    }

    socket = BPF_CORE_READ(file, private_data);
    if (!socket) {
        return submit_unknown_event(ret);
    }

    sock = BPF_CORE_READ(socket, sk);
    if (!sock) {
        return submit_unknown_event(ret);
    }

    event = bpf_ringbuf_reserve(&accept_events, sizeof(*event), 0);
    if (!event) {
        increment_accept_drops();
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->pid = id >> 32;
    event->fd = ret;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    fill_event_from_socket(event, sock);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* trace_accept4_exit turns a successful accept4 return into a userspace event. */
SEC("kretprobe/accept4_exit")
int BPF_KRETPROBE(trace_accept4_exit, int ret)
{
    if (ret < 0) {
        return 0;
    }

    return submit_socket_event(ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
