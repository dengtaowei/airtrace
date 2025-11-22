#ifndef __GENERATED_STRUCTS_H__
#define __GENERATED_STRUCTS_H__

/*
 * 自动生成的结构体定义
 * 注释格式: [起始偏移-结束偏移] 大小
 */

#include <linux/types.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/timer.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

struct tcp_sock {
    unsigned char __padding1[1008]; /* [0-1007] 1008 bytes */
    u32 rcv_nxt; /* [1008-1011] 4 bytes */
    unsigned char __padding2[40]; /* [1012-1051] 40 bytes */
    u32 snd_una; /* [1052-1055] 4 bytes */
    unsigned char __padding3[196]; /* [1056-1251] 196 bytes */
    u32 packets_out; /* [1252-1255] 4 bytes */
    u32 retrans_out; /* [1256-1259] 4 bytes */
    unsigned char __padding4[468]; /* [1260-1727] 468 bytes */
} __attribute__((__packed__)); /* total size: 1728 bytes */

struct timer_list {
    unsigned char __padding1[8]; /* [0-7] 8 bytes */
    unsigned long expires; /* [8-11] 4 bytes */
    unsigned char __padding2[8]; /* [12-19] 8 bytes */
} __attribute__((__packed__)); /* total size: 20 bytes */

struct inet_connection_sock {
    unsigned char __padding1[740]; /* [0-739] 740 bytes */
    u32 icsk_timeout; /* [740-743] 4 bytes */
    struct timer_list icsk_retransmit_timer; /* [744-763] 20 bytes */
    unsigned char __padding2[61]; /* [764-824] 61 bytes */
    u8 icsk_retransmits; /* [825-825] 1 bytes */
    u8 icsk_pending; /* [826-826] 1 bytes */
    unsigned char __padding3[157]; /* [827-983] 157 bytes */
} __attribute__((__packed__)); /* total size: 984 bytes */

struct sock_common {
    __be32 skc_daddr; /* [0-3] 4 bytes */
    __be32 skc_rcv_saddr; /* [4-7] 4 bytes */
    unsigned char __padding1[4]; /* [8-11] 4 bytes */
    __be16 skc_dport; /* [12-13] 2 bytes */
    u16 skc_num; /* [14-15] 2 bytes */
    u16 skc_family; /* [16-17] 2 bytes */
    u8 skc_state; /* [18-18] 1 bytes */
    unsigned char __padding2[61]; /* [19-79] 61 bytes */
} __attribute__((__packed__)); /* total size: 80 bytes */

struct tcp_skb_cb {
    u32 seq; /* [0-3] 4 bytes */
    unsigned char __padding1[8]; /* [4-11] 8 bytes */
    u8 tcp_flags; /* [12-12] 1 bytes */
    unsigned char __padding2[35]; /* [13-47] 35 bytes */
} __attribute__((__packed__)); /* total size: 48 bytes */

struct __sk_buff {
    unsigned char __padding1[76]; /* [0-75] 76 bytes */
    u32 data; /* [76-79] 4 bytes */
    u32 data_end; /* [80-83] 4 bytes */
    unsigned char __padding2[108]; /* [84-191] 108 bytes */
} __attribute__((__packed__)); /* total size: 192 bytes */

struct netdev_queue {
    unsigned char __padding1[72]; /* [0-71] 72 bytes */
    unsigned long trans_start; /* [72-75] 4 bytes */
    unsigned long state; /* [76-79] 4 bytes */
    unsigned char __padding2[176]; /* [80-255] 176 bytes */
} __attribute__((__packed__)); /* total size: 256 bytes */

struct net_device {
    unsigned char  name[16]; /* [0-15] 16 bytes */
    unsigned char __padding1[112]; /* [16-127] 112 bytes */
    int ifindex; /* [128-131] 4 bytes */
    unsigned char __padding2[1276]; /* [132-1407] 1276 bytes */
} __attribute__((__packed__)); /* total size: 1408 bytes */

struct qdisc_skb_head {
    unsigned char __padding1[8]; /* [0-7] 8 bytes */
    unsigned int qlen; /* [8-11] 4 bytes */
    unsigned char __padding2[4]; /* [12-15] 4 bytes */
} __attribute__((__packed__)); /* total size: 16 bytes */

struct Qdisc {
    unsigned char __padding1[8]; /* [0-7] 8 bytes */
    unsigned int flags; /* [8-11] 4 bytes */
    unsigned char __padding2[28]; /* [12-39] 28 bytes */
    u32 dev_queue; /* [40-43] 4 bytes */
    unsigned char __padding3[36]; /* [44-79] 36 bytes */
    struct qdisc_skb_head q; /* [80-95] 16 bytes */
    unsigned char __padding4[160]; /* [96-255] 160 bytes */
} __attribute__((__packed__)); /* total size: 256 bytes */

struct sk_buff {
    unsigned char __padding1[8]; /* [0-7] 8 bytes */
    struct net_device * dev; /* [8-11] 4 bytes */
    struct sock * sk; /* [12-15] 4 bytes */
    unsigned char __padding2[8]; /* [16-23] 8 bytes */
    unsigned char  cb[48]; /* [24-71] 48 bytes */
    unsigned char __padding3[40]; /* [72-111] 40 bytes */
    u32 skb_iif; /* [112-115] 4 bytes */
    unsigned char __padding4[24]; /* [116-139] 24 bytes */
    __be16 protocol; /* [140-141] 2 bytes */
    u16 transport_header; /* [142-143] 2 bytes */
    u16 network_header; /* [144-145] 2 bytes */
    u16 mac_header; /* [146-147] 2 bytes */
    unsigned char __padding5[8]; /* [148-155] 8 bytes */
    void * head; /* [156-159] 4 bytes */
    unsigned char __padding6[16]; /* [160-175] 16 bytes */
} __attribute__((__packed__)); /* total size: 176 bytes */

struct sk_buff_head {
    unsigned char __padding1[8]; /* [0-7] 8 bytes */
    unsigned int qlen; /* [8-11] 4 bytes */
    unsigned char __padding2[4]; /* [12-15] 4 bytes */
} __attribute__((__packed__)); /* total size: 16 bytes */

struct socket {
    unsigned char __padding1[16]; /* [0-15] 16 bytes */
    struct sock * sk; /* [16-19] 4 bytes */
    unsigned char __padding2[108]; /* [20-127] 108 bytes */
} __attribute__((__packed__)); /* total size: 128 bytes */

struct sock {
    struct sock_common __sk_common; /* [0-79] 80 bytes */
    unsigned char __padding1[56]; /* [80-135] 56 bytes */
    struct sk_buff_head sk_receive_queue; /* [136-151] 16 bytes */
    unsigned char __padding2[76]; /* [152-227] 76 bytes */
    struct sk_buff_head sk_write_queue; /* [228-243] 16 bytes */
    unsigned char __padding3[96]; /* [244-339] 96 bytes */
    u16 sk_protocol; /* [340-341] 2 bytes */
    unsigned char __padding4[154]; /* [342-495] 154 bytes */
} __attribute__((__packed__)); /* total size: 496 bytes */

#endif /* __GENERATED_STRUCTS_H__ */