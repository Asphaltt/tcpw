// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "bpf_core_read.h"
#include "bpf_tracing_net.h"

#define TASK_COMM_LEN 16
#define UNIX_PATH_MAX 108

#define SOCK_PATH_OFFSET    \
    (offsetof(struct unix_address, name) + offsetof(struct sockaddr_un, sun_path))

__u32 ready SEC(".data.ready") = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} tcpw_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096<<8);
} events SEC(".maps");

struct event {
    __u8 comm[TASK_COMM_LEN];
    __u32 pid;
    __u16 family;
    __u8 is_active;
    __u8 pad;
    __u8 proto_name[32];
    union {
        struct {
            __u32 portpair;
            union {
                __u64 addrpair;
                struct {
                    __u8 raddr_v6[16];
                    __u8 laddr_v6[16];
                };
            };
        } __attribute__((packed));
        __u8 unix_path[UNIX_PATH_MAX];
    };
} __attribute__((packed));

/* This helper checks if a socket is a full socket,
 * ie _not_ a timewait or request socket.
 */
static inline bool sk_fullsock(__u16 state)
{
    return (1 << state) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV);
}

static __always_inline void
read_unix_path(struct unix_sock *sk, struct event *event)
{
    struct unix_address *addr;
    __u8 one_byte = 0;
    char *sock_path;

    addr = BPF_CORE_READ(sk, addr);
    if (!BPF_CORE_READ(addr, len))
        return;

    // 1. Use offset instead of BPF_CORE_READ() to get the address of the path.
    // 2. Check if it's "@/path/to/unix.sock".

    sock_path = (char *) addr + SOCK_PATH_OFFSET;
    bpf_probe_read_kernel(&one_byte, 1, sock_path);
    if (one_byte)
        bpf_probe_read_kernel_str(event->unix_path, UNIX_PATH_MAX, sock_path);
    else
        bpf_probe_read_kernel_str(event->unix_path, UNIX_PATH_MAX, sock_path + 1);
}

static __always_inline int
emit_event(__u32 pid, struct sock *sk, const bool is_active)
{
    struct event *event;
    bool valid = true;
    __u16 family;
    __u16 state;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return BPF_OK;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->pid = pid;
    event->family = family;
    event->is_active = is_active;
    BPF_CORE_READ_STR_INTO(&event->proto_name, sk, __sk_common.skc_prot, name);
    switch (family) {
    case AF_INET:
        BPF_CORE_READ_INTO(&event->portpair, sk, __sk_common.skc_dport);
        valid = event->portpair != 0;
        if (valid)
            BPF_CORE_READ_INTO(&event->addrpair, sk, __sk_common.skc_addrpair);
        break;

    case AF_INET6:
        BPF_CORE_READ_INTO(&event->portpair, sk, __sk_common.skc_dport);
        valid = event->portpair != 0;
        if (valid) {
            bpf_probe_read_kernel(&event->raddr_v6, sizeof(event->raddr_v6),
                                  &sk->__sk_common.skc_v6_daddr);
            bpf_probe_read_kernel(&event->laddr_v6, sizeof(event->laddr_v6),
                                  &sk->__sk_common.skc_v6_rcv_saddr);
        }
        break;

    case AF_UNIX:
        state = BPF_CORE_READ(sk, __sk_common.skc_state);
        if (sk_fullsock(state))
            read_unix_path((struct unix_sock *) sk, event);
        valid = event->unix_path[0] != '\0';
        break;

    default:
        valid = false;
        break;
    }

    if (valid)
        bpf_ringbuf_submit(event, 0);
    else
        bpf_ringbuf_discard(event, 0);

    return BPF_OK;
}

static __always_inline int
trace_sock(struct socket *sock, const bool is_active)
{
    struct sock *sk;
    __u32 pid;

    if (!ready)
        return BPF_OK;

    sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return BPF_OK;

    pid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&tcpw_pids, &pid))
        return BPF_OK;

    return emit_event(pid, sk, is_active);
}

SEC("fexit/connect")
int BPF_PROG(fexit_connect, struct socket *sock, struct sockaddr *uaddr,
             int addr_len, int flags, int retval)
{
    return trace_sock(sock, true);
}

SEC("fexit/accept")
int BPF_PROG(fexit_accept, struct socket *sock, struct socket *newsock,
             struct proto_accept_arg *arg, int retval)
{
    return trace_sock(newsock, false);
}

SEC("tp/sched/sched_process_fork")
int tp_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid = ctx->child_pid;
    __u32 pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&tcpw_pids, &pid)) {
        bpf_map_update_elem(&tcpw_pids, &parent_pid, &pid, BPF_ANY);
        bpf_map_update_elem(&tcpw_pids, &child_pid, &parent_pid, BPF_ANY);
    }

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
