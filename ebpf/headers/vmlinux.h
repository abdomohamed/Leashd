/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal vmlinux.h for leashd — contains only the kernel types used by
 * ebpf/leashd.c.  Defining __VMLINUX_H__ causes bpf_tracing.h to use
 * kernel-style register names (si, di, ax…) instead of userspace names
 * (rsi, rdi, rax…) when expanding PT_REGS_PARM*.
 *
 * This file is committed to the repo so CI does not need bpftool to
 * generate it from a running kernel's BTF.
 *
 * To regenerate from a kernel with BTF:
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/headers/vmlinux.h
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/* Integer types ----------------------------------------------------------- */
typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;
typedef signed char        __s8;
typedef short              __s16;
typedef int                __s32;
typedef long long          __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;
typedef __u16 __sum16;
typedef __u32 __wsum;   /* checksum type used by bpf_helper_defs.h */

/* x86-64 struct pt_regs (kernel naming, not uapi naming) ------------------
 * Used by kprobe programs via PT_REGS_PARM2 etc. from bpf_tracing.h.
 * When __VMLINUX_H__ is defined, bpf_tracing.h uses kernel register names
 * (si, di, ax…) not userspace names (rsi, rdi, rax…).
 */
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;   /* PARM2 (RSI) */
	unsigned long di;   /* PARM1 (RDI) */
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
};

/* IPv4 socket address ----------------------------------------------------- */
struct in_addr {
	__u32 s_addr;
};

struct sockaddr {
	__u16 sa_family;
	char  sa_data[14];
};

struct sockaddr_in {
	__u16          sin_family;
	__be16         sin_port;
	struct in_addr sin_addr;
	__u8           sin_zero[8];
};

/* IPv4 header ------------------------------------------------------------- */
struct iphdr {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8 ihl:4;
	__u8 version:4;
#else
	__u8 version:4;
	__u8 ihl:4;
#endif
	__u8   tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8   ttl;
	__u8   protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};

/* cgroup/skb context -------------------------------------------------------
 * Shadow struct for struct sk_buff in cgroup/skb BPF programs.
 * Field layout must match linux/bpf.h struct __sk_buff exactly so the BPF
 * verifier correctly rewrites member accesses.
 */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;       /* AF_INET / AF_INET6 */
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
};

/* BPF map types ----------------------------------------------------------- */
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_STACK_TRACE,
	BPF_MAP_TYPE_CGROUP_ARRAY,
	BPF_MAP_TYPE_LRU_HASH,
	BPF_MAP_TYPE_LRU_PERCPU_HASH,
	BPF_MAP_TYPE_LPM_TRIE,
	BPF_MAP_TYPE_ARRAY_OF_MAPS,
	BPF_MAP_TYPE_HASH_OF_MAPS,
	BPF_MAP_TYPE_DEVMAP,
	BPF_MAP_TYPE_SOCKMAP,
	BPF_MAP_TYPE_CPUMAP,
	BPF_MAP_TYPE_XSKMAP,
	BPF_MAP_TYPE_SOCKHASH,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_CGROUP_STORAGE = BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_QUEUE,
	BPF_MAP_TYPE_STACK,
	BPF_MAP_TYPE_SK_STORAGE,
	BPF_MAP_TYPE_DEVMAP_HASH,
	BPF_MAP_TYPE_STRUCT_OPS,
	BPF_MAP_TYPE_RINGBUF,
	BPF_MAP_TYPE_INODE_STORAGE,
	BPF_MAP_TYPE_TASK_STORAGE,
	BPF_MAP_TYPE_BLOOM_FILTER,
	BPF_MAP_TYPE_USER_RINGBUF,
	BPF_MAP_TYPE_CGRP_STORAGE,
};

/* BPF map creation flags -------------------------------------------------- */
#define BPF_F_NO_PREALLOC  (1U << 0)

/* Network address families ------------------------------------------------ */
#define AF_UNSPEC  0
#define AF_INET    2
#define AF_INET6   10

/* IP protocols ------------------------------------------------------------ */
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17

#endif /* __VMLINUX_H__ */
