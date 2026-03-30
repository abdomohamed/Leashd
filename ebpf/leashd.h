#pragma once

/* Integer types come from vmlinux.h (included before this header). */

/* Verdict values stored in the policy map and ring buffer events. */
#define VERDICT_ALLOW  0
#define VERDICT_WARN   1
#define VERDICT_BLOCK  2

/* Key for the BPF_MAP_TYPE_LPM_TRIE policy map. */
struct policy_lpm_key {
    __u32 prefixlen;
    __u32 ip;          /* network byte order */
};

/* Value for the policy map. */
struct policy_val {
    __u8  verdict;     /* VERDICT_* */
    __u8  pad[3];
};

/*
 * Event emitted to userspace via the ring buffer.
 * Total size: 56 bytes (8-byte aligned).
 */
struct connect_event {
    __u64 timestamp_ns;   /* bpf_ktime_get_ns() */
    __u32 pid;
    __u32 tgid;
    __u32 dst_ip;         /* network byte order */
    __u16 dst_port;       /* network byte order */
    __u8  protocol;       /* IPPROTO_TCP=6 / IPPROTO_UDP=17 */
    __u8  verdict;        /* VERDICT_* as determined by BPF */
    __u64 cgroup_id;
    char  comm[16];       /* task comm (process name) */
    __u8  _pad[6];
};
