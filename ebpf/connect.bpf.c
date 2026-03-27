#include "vmlinux.h"

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
} connect_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} connect_drop_stats SEC(".maps");

/* increment_connect_drops records ring buffer reserve failures for the connect probe. */
static __always_inline void increment_connect_drops(void)
{
    __u32 key = 0;
    __u64 *value;

    value = bpf_map_lookup_elem(&connect_drop_stats, &key);
    if (!value) {
        return;
    }

    __sync_fetch_and_add(value, 1);
}

/* submit_connect_ipv4_event emits a connect event when the destination is IPv4. */
static __always_inline int submit_connect_ipv4_event(int sockfd, void *uservaddr, int addrlen)
{
    struct sockaddr_in addr = {};
    struct connect_event *event;
    __u64 id = bpf_get_current_pid_tgid();

    if (addrlen < sizeof(addr)) {
        return 0;
    }

    if (bpf_probe_read_user(&addr, sizeof(addr), uservaddr) < 0) {
        return 0;
    }

    if (addr.sin_family != AF_INET) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&connect_events, sizeof(*event), 0);
    if (!event) {
        increment_connect_drops();
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->pid = id >> 32;
    event->fd = sockfd;
    event->family = addr.sin_family;
    event->port = bpf_ntohs(addr.sin_port);
    __builtin_memcpy(event->addr, &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr));
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* submit_connect_ipv6_event emits a connect event when the destination is IPv6. */
static __always_inline int submit_connect_ipv6_event(int sockfd, void *uservaddr, int addrlen)
{
    struct sockaddr_in6 addr = {};
    struct connect_event *event;
    __u64 id = bpf_get_current_pid_tgid();

    if (addrlen < sizeof(addr)) {
        return 0;
    }

    if (bpf_probe_read_user(&addr, sizeof(addr), uservaddr) < 0) {
        return 0;
    }

    if (addr.sin6_family != AF_INET6) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&connect_events, sizeof(*event), 0);
    if (!event) {
        increment_connect_drops();
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->pid = id >> 32;
    event->fd = sockfd;
    event->family = addr.sin6_family;
    event->port = bpf_ntohs(addr.sin6_port);
    __builtin_memcpy(event->addr, addr.sin6_addr.in6_u.u6_addr8, sizeof(event->addr));
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* submit_unknown_connect_event emits a connect event even when address parsing fails. */
static __always_inline int submit_unknown_connect_event(int sockfd)
{
    struct connect_event *event;
    __u64 id = bpf_get_current_pid_tgid();

    event = bpf_ringbuf_reserve(&connect_events, sizeof(*event), 0);
    if (!event) {
        increment_connect_drops();
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->pid = id >> 32;
    event->fd = sockfd;
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* trace_connect_enter captures outbound connection attempts from sys_connect arguments. */
SEC("kprobe/connect_enter")
int trace_connect_enter(struct pt_regs *ctx)
{
    int sockfd = (int)PT_REGS_PARM1(ctx);
    void *uservaddr = (void *)PT_REGS_PARM2(ctx);
    int addrlen = (int)PT_REGS_PARM3(ctx);
    __u16 family = 0;

    if (!uservaddr) {
        return 0;
    }

    if (bpf_probe_read_user(&family, sizeof(family), uservaddr) < 0) {
        submit_unknown_connect_event(sockfd);
        return 0;
    }

    if (family == AF_INET) {
        return submit_connect_ipv4_event(sockfd, uservaddr, addrlen);
    }

    if (family == AF_INET6) {
        return submit_connect_ipv6_event(sockfd, uservaddr, addrlen);
    }

    return submit_unknown_connect_event(sockfd);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
