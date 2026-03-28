// SPDX-License-Identifier: GPL-2.0
// leashd eBPF kernel program
// Attaches to tcp_v4_connect (kprobe) and cgroup/skb to enforce per-project
// network policy loaded from userspace into BPF maps.

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "leashd.h"

char LICENSE[] SEC("license") = "GPL";

/* ------------------------------------------------------------------ */
/* Maps                                                                  */
/* ------------------------------------------------------------------ */

/*
 * policy_map: LPM trie for IP/CIDR → verdict lookups.
 * Written by the Go daemon, read by kprobes and cgroup/skb.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct policy_lpm_key);
    __type(value, struct policy_val);
} policy_map SEC(".maps");

/*
 * tracked_cgroups: set of cgroup IDs being monitored by leashd.
 * The kprobe checks this before doing anything so untracked processes
 * are a zero-cost no-op.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);   /* cgroup_id */
    __type(value, __u8);  /* always 1 */
} tracked_cgroups SEC(".maps");

/*
 * events: ring buffer for streaming connect events to userspace.
 * 4 MiB — tunable via a future config option.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

/* ------------------------------------------------------------------ */
/* Helpers                                                               */
/* ------------------------------------------------------------------ */

static __always_inline __u8 lookup_verdict(__u32 dst_ip)
{
    struct policy_lpm_key key = {
        .prefixlen = 32,
        .ip        = dst_ip,
    };
    struct policy_val *val = bpf_map_lookup_elem(&policy_map, &key);
    if (val)
        return val->verdict;
    return VERDICT_WARN; /* default: emit event, let userspace decide */
}

static __always_inline void emit_event(
    __u32 pid, __u32 tgid, __u32 dst_ip, __u16 dst_port,
    __u8 protocol, __u8 verdict, __u64 cgroup_id)
{
    struct connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = pid;
    e->tgid         = tgid;
    e->dst_ip       = dst_ip;
    e->dst_port     = dst_port;
    e->protocol     = protocol;
    e->verdict      = verdict;
    e->cgroup_id    = cgroup_id;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
}

/* ------------------------------------------------------------------ */
/* Program 1: kprobe on tcp_v4_connect                                   */
/* ------------------------------------------------------------------ */

SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_connect(struct pt_regs *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    /* Fast path: skip if this cgroup isn't tracked. */
    __u8 *tracked = bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id);
    if (!tracked)
        return 0;

    /* tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
     * arg2 = uaddr (struct sockaddr_in *) */
    struct sockaddr_in *uaddr = (struct sockaddr_in *)PT_REGS_PARM2(ctx);
    if (!uaddr)
        return 0;

    __u32 dst_ip   = 0;
    __u16 dst_port = 0;
    bpf_probe_read_user(&dst_ip,   sizeof(dst_ip),   &uaddr->sin_addr.s_addr);
    bpf_probe_read_user(&dst_port, sizeof(dst_port), &uaddr->sin_port);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    __u32 tgid     = (__u32)pid_tgid;

    __u8 verdict = lookup_verdict(dst_ip);
    emit_event(pid, tgid, dst_ip, dst_port, IPPROTO_TCP, verdict, cgroup_id);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Program 2: kprobe on ip4_datagram_connect (UDP)                       */
/* ------------------------------------------------------------------ */

SEC("kprobe/ip4_datagram_connect")
int kprobe_udp_connect(struct pt_regs *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    __u8 *tracked = bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id);
    if (!tracked)
        return 0;

    struct sockaddr_in *uaddr = (struct sockaddr_in *)PT_REGS_PARM2(ctx);
    if (!uaddr)
        return 0;

    __u32 dst_ip   = 0;
    __u16 dst_port = 0;
    bpf_probe_read_user(&dst_ip,   sizeof(dst_ip),   &uaddr->sin_addr.s_addr);
    bpf_probe_read_user(&dst_port, sizeof(dst_port), &uaddr->sin_port);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    __u32 tgid     = (__u32)pid_tgid;

    __u8 verdict = lookup_verdict(dst_ip);
    emit_event(pid, tgid, dst_ip, dst_port, IPPROTO_UDP, verdict, cgroup_id);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Program 3: cgroup/skb egress filter — enforces BLOCK verdict          */
/* ------------------------------------------------------------------ */

SEC("cgroup/skb")
int cgroup_skb_egress(struct __sk_buff *skb)
{
    /* Only process IPv4. */
    if (skb->family != AF_INET)
        return 1; /* allow */

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *tracked   = bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id);
    if (!tracked)
        return 1; /* allow — not a tracked cgroup */

    /* Read destination IP from the packet. */
    __u32 dst_ip = 0;
    bpf_skb_load_bytes(skb, offsetof(struct iphdr, daddr), &dst_ip, sizeof(dst_ip));

    struct policy_lpm_key key = { .prefixlen = 32, .ip = dst_ip };
    struct policy_val *val = bpf_map_lookup_elem(&policy_map, &key);
    if (val && val->verdict == VERDICT_BLOCK)
        return 0; /* drop */

    return 1; /* allow */
}
