#ifndef __AIR_TRACE__
#define __AIR_TRACE__

#define CONFIG_MAP_SIZE	1024
#define MAX_MAC_FILTER 32

struct event_t {
    u32 msglen;
    u64 timestamp_ns;
    u8 message[2048];
};

typedef struct {
    u8 addr[MAX_MAC_FILTER][6];
    u32 mac_num;
} pkt_args_t;

typedef struct {
	pkt_args_t pkt;
} bpf_args_t;

#endif