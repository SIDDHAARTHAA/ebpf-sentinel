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

struct accept_args {
    __u64 sockaddr_ptr;
    __u64 addrlen_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct accept_args);
    __uint(max_entries, 10240);
} inflight_accepts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} accept_events SEC(".maps");

/* trace_accept4_enter stores accept4 arguments so the return probe can read them later. */
SEC("kprobe/accept4_enter")
int BPF_KPROBE(trace_accept4_enter, int sockfd, void *upeer_sockaddr, int *upeer_addrlen,
               int flags)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct accept_args args = {
        .sockaddr_ptr = (__u64)upeer_sockaddr,
        .addrlen_ptr = (__u64)upeer_addrlen,
    };

    bpf_map_update_elem(&inflight_accepts, &id, &args, BPF_ANY);
    return 0;
}

/* submit_ipv4_event emits an accept event when the peer address is IPv4. */
static __always_inline int submit_ipv4_event(__s32 ret, struct accept_args *args)
{
    struct sockaddr_in addr = {};
    __u32 addrlen = 0;
    struct accept_event *event;
    __u64 id = bpf_get_current_pid_tgid();

    if (bpf_probe_read_user(&addrlen, sizeof(addrlen), (void *)args->addrlen_ptr) < 0) {
        return 0;
    }

    if (addrlen < sizeof(addr)) {
        return 0;
    }

    if (bpf_probe_read_user(&addr, sizeof(addr), (void *)args->sockaddr_ptr) < 0) {
        return 0;
    }

    if (addr.sin_family != AF_INET) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&accept_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->pid = id >> 32;
    event->fd = ret;
    event->family = addr.sin_family;
    event->port = bpf_ntohs(addr.sin_port);
    __builtin_memcpy(event->addr, &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr));
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* submit_ipv6_event emits an accept event when the peer address is IPv6. */
static __always_inline int submit_ipv6_event(__s32 ret, struct accept_args *args)
{
    struct sockaddr_in6 addr = {};
    __u32 addrlen = 0;
    struct accept_event *event;
    __u64 id = bpf_get_current_pid_tgid();

    if (bpf_probe_read_user(&addrlen, sizeof(addrlen), (void *)args->addrlen_ptr) < 0) {
        return 0;
    }

    if (addrlen < sizeof(addr)) {
        return 0;
    }

    if (bpf_probe_read_user(&addr, sizeof(addr), (void *)args->sockaddr_ptr) < 0) {
        return 0;
    }

    if (addr.sin6_family != AF_INET6) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&accept_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->pid = id >> 32;
    event->fd = ret;
    event->family = addr.sin6_family;
    event->port = bpf_ntohs(addr.sin6_port);
    __builtin_memcpy(event->addr, addr.sin6_addr.in6_u.u6_addr8, sizeof(event->addr));
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* submit_unknown_event emits an accept event even when peer parsing fails. */
static __always_inline int submit_unknown_event(__s32 ret)
{
    struct accept_event *event;
    __u64 id = bpf_get_current_pid_tgid();

    event = bpf_ringbuf_reserve(&accept_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->pid = id >> 32;
    event->fd = ret;
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* trace_accept4_exit turns a successful accept4 return into a userspace event. */
SEC("kretprobe/accept4_exit")
int BPF_KRETPROBE(trace_accept4_exit, int ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct accept_args *args;
    __u16 family = 0;

    args = bpf_map_lookup_elem(&inflight_accepts, &id);
    if (!args) {
        return 0;
    }

    if (ret < 0 || !args->sockaddr_ptr || !args->addrlen_ptr) {
        goto cleanup;
    }

    if (bpf_probe_read_user(&family, sizeof(family), (void *)args->sockaddr_ptr) < 0) {
        submit_unknown_event(ret);
        goto cleanup;
    }

    if (family == AF_INET) {
        submit_ipv4_event(ret, args);
    } else if (family == AF_INET6) {
        submit_ipv6_event(ret, args);
    } else {
        submit_unknown_event(ret);
    }

cleanup:
    bpf_map_delete_elem(&inflight_accepts, &id);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
