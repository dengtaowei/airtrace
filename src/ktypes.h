#ifndef __AIR_TRACE_KTYPES_H__
#define __AIR_TRACE_KTYPES_H__
#if defined(__TARGET_ARCH_arm)
typedef long long unsigned int __u64;
typedef unsigned int __u32;
typedef short unsigned int __u16;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

typedef unsigned char __u8;

typedef __u8 u8;

typedef __u32 u32;

typedef long long int __s64;

typedef __s64 s64;

typedef __u16 u16;

typedef int __s32;

typedef __u64 u64;

typedef __u16 __sum16;

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
	BPF_MAP_TYPE_BLOOM_FILTER = 30,
	BPF_MAP_TYPE_USER_RINGBUF = 31,
	BPF_MAP_TYPE_CGRP_STORAGE = 32,
	BPF_MAP_TYPE_ARENA = 33,
	__MAX_BPF_MAP_TYPE = 34,
};

enum {
	BPF_F_INDEX_MASK = 4294967295ULL,
	BPF_F_CURRENT_CPU = 4294967295ULL,
	BPF_F_CTXLEN_MASK = 4503595332403200ULL,
};

struct my_pt_regs {
	unsigned int uregs[18];
};


#elif defined(__TARGET_ARCH_arm64)
typedef long long unsigned int __u64;
typedef unsigned int __u32;
typedef short unsigned int __u16;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

typedef unsigned char __u8;

typedef __u8 u8;
typedef __u32 u32;
typedef long long int __s64;
typedef __s64 s64;
typedef __u16 u16;
typedef int __s32;

typedef __s32 s32;

typedef __u64 u64;

typedef __u16 __sum16;

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
	BPF_MAP_TYPE_BLOOM_FILTER = 30,
	BPF_MAP_TYPE_USER_RINGBUF = 31,
	BPF_MAP_TYPE_CGRP_STORAGE = 32,
	BPF_MAP_TYPE_ARENA = 33,
	__MAX_BPF_MAP_TYPE = 34,
};

enum {
	BPF_F_INDEX_MASK = 4294967295ULL,
	BPF_F_CURRENT_CPU = 4294967295ULL,
	BPF_F_CTXLEN_MASK = 4503595332403200ULL,
};

struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};

struct frame_record {
	u64 fp;
	u64 lr;
};

struct frame_record_meta {
	struct frame_record record;
	u64 type;
};

struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			u64 regs[31];
			u64 sp;
			u64 pc;
			u64 pstate;
		};
	};
	u64 orig_x0;
	s32 syscallno;
	u32 pmr;
	u64 sdei_ttbr1;
	struct frame_record_meta stackframe;
	u64 lockdep_hardirqs;
	u64 exit_rcu;
};
#elif defined(__TARGET_ARCH_x86)
typedef long long unsigned int __u64;
typedef unsigned int __u32;
typedef short unsigned int __u16;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

typedef unsigned char __u8;

typedef __u8 u8;
typedef __u32 u32;
typedef long long int __s64;
typedef __s64 s64;
typedef __u16 u16;
typedef int __s32;

typedef __s32 s32;

typedef __u64 u64;

typedef __u16 __sum16;

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
	BPF_MAP_TYPE_BLOOM_FILTER = 30,
	BPF_MAP_TYPE_USER_RINGBUF = 31,
	BPF_MAP_TYPE_CGRP_STORAGE = 32,
	BPF_MAP_TYPE_ARENA = 33,
	__MAX_BPF_MAP_TYPE = 34,
};

enum {
	BPF_F_INDEX_MASK = 4294967295ULL,
	BPF_F_CURRENT_CPU = 4294967295ULL,
	BPF_F_CTXLEN_MASK = 4503595332403200ULL,
};

struct fred_cs {
	u64 cs: 16;
	u64 sl: 2;
	u64 wfe: 1;
};
struct fred_ss {
	u64 ss: 16;
	u64 sti: 1;
	u64 swevent: 1;
	u64 nmi: 1;
	int: 13;
	u64 vector: 8;
	short: 8;
	u64 type: 4;
	char: 4;
	u64 enclave: 1;
	u64 lm: 1;
	u64 nested: 1;
	char: 1;
	u64 insnlen: 4;
};

struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	union {
		u16 cs;
		u64 csx;
		struct fred_cs fred_cs;
	};
	long unsigned int flags;
	long unsigned int sp;
	union {
		u16 ss;
		u64 ssx;
		struct fred_ss fred_ss;
	};
};

#endif

struct ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__be16 h_proto;
}__attribute__((__packed__));

struct iphdr {
	__u8 ihl: 4;
	__u8 version: 4;
	__u8 tos;
	__be16 tot_len;  // Including header information
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	union {
		struct {
			__be32 saddr;
			__be32 daddr;
		};
		struct {
			__be32 saddr;
			__be32 daddr;
		} addrs;
	};
}__attribute__((__packed__));


struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
}__attribute__((__packed__));


struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
}__attribute__((__packed__));

struct ipv6hdr {
	__u8 priority: 4;
	__u8 version: 4;
	__u8 flow_lbl[3];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	union {
		struct {
			struct in6_addr saddr;
			struct in6_addr daddr;
		};
		struct {
			struct in6_addr saddr;
			struct in6_addr daddr;
		} addrs;
	};
}__attribute__((__packed__));


struct icmp6hdr {
	__u8 icmp6_type;
	__u8 icmp6_code;
	__sum16 icmp6_cksum;
	// union {
	// 	__be32 un_data32[1];
	// 	__be16 un_data16[2];
	// 	__u8 un_data8[4];
	// 	struct icmpv6_echo u_echo;
	// 	struct icmpv6_nd_advt u_nd_advt;
	// 	struct icmpv6_nd_ra u_nd_ra;
	// } icmp6_dataun;
}__attribute__((__packed__));

#endif