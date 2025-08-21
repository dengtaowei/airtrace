#ifndef __AIR_TRACE__
#define __AIR_TRACE__

#define CONFIG_MAP_SIZE	1024

struct event_t {
    u32 msglen;
    u8 message[2048];
};

typedef struct {
    u8 addr[6];
} pkt_args_t;

typedef struct {
	pkt_args_t pkt;
} bpf_args_t;

#endif