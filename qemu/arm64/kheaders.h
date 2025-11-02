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
    unsigned char __padding1[1392]; /* [0-1391] 1392 bytes */
    u32 rcv_nxt; /* [1392-1395] 4 bytes */
    unsigned char __padding2[40]; /* [1396-1435] 40 bytes */
    u32 snd_una; /* [1436-1439] 4 bytes */
    unsigned char __padding3[212]; /* [1440-1651] 212 bytes */
    u32 packets_out; /* [1652-1655] 4 bytes */
    u32 retrans_out; /* [1656-1659] 4 bytes */
    unsigned char __padding4[524]; /* [1660-2183] 524 bytes */
} __attribute__((__packed__)); /* total size: 2184 bytes */

struct timer_list {
    unsigned char __padding1[16]; /* [0-15] 16 bytes */
    unsigned long expires; /* [16-23] 8 bytes */
    unsigned char __padding2[16]; /* [24-39] 16 bytes */
} __attribute__((__packed__)); /* total size: 40 bytes */

struct inet_connection_sock {
    unsigned char __padding1[1056]; /* [0-1055] 1056 bytes */
    u64 icsk_timeout; /* [1056-1063] 8 bytes */
    struct timer_list icsk_retransmit_timer; /* [1064-1103] 40 bytes */
    unsigned char __padding2[105]; /* [1104-1208] 105 bytes */
    u8 icsk_retransmits; /* [1209-1209] 1 bytes */
    u8 icsk_pending; /* [1210-1210] 1 bytes */
    unsigned char __padding3[157]; /* [1211-1367] 157 bytes */
} __attribute__((__packed__)); /* total size: 1368 bytes */

struct sock_common {
    __be32 skc_daddr; /* [0-3] 4 bytes */
    __be32 skc_rcv_saddr; /* [4-7] 4 bytes */
    unsigned char __padding1[4]; /* [8-11] 4 bytes */
    __be16 skc_dport; /* [12-13] 2 bytes */
    u16 skc_num; /* [14-15] 2 bytes */
    u16 skc_family; /* [16-17] 2 bytes */
    u8 skc_state; /* [18-18] 1 bytes */
    unsigned char __padding2[37]; /* [19-55] 37 bytes */
    struct in6_addr skc_v6_daddr; /* [56-71] 16 bytes */
    struct in6_addr skc_v6_rcv_saddr; /* [72-87] 16 bytes */
    unsigned char __padding3[48]; /* [88-135] 48 bytes */
} __attribute__((__packed__)); /* total size: 136 bytes */

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
    unsigned char __padding1[136]; /* [0-135] 136 bytes */
    unsigned long trans_start; /* [136-143] 8 bytes */
    unsigned long state; /* [144-151] 8 bytes */
    unsigned char __padding2[168]; /* [152-319] 168 bytes */
} __attribute__((__packed__)); /* total size: 320 bytes */

struct net_device {
    unsigned char  name[16]; /* [0-15] 16 bytes */
    unsigned char __padding1[208]; /* [16-223] 208 bytes */
    int ifindex; /* [224-227] 4 bytes */
    unsigned char __padding2[2204]; /* [228-2431] 2204 bytes */
} __attribute__((__packed__)); /* total size: 2432 bytes */

struct qdisc_skb_head {
    unsigned char __padding1[16]; /* [0-15] 16 bytes */
    unsigned int qlen; /* [16-19] 4 bytes */
    unsigned char __padding2[4]; /* [20-23] 4 bytes */
} __attribute__((__packed__)); /* total size: 24 bytes */

struct Qdisc {
    unsigned char __padding1[16]; /* [0-15] 16 bytes */
    unsigned int flags; /* [16-19] 4 bytes */
    unsigned char __padding2[44]; /* [20-63] 44 bytes */
    u64 dev_queue; /* [64-71] 8 bytes */
    unsigned char __padding3[80]; /* [72-151] 80 bytes */
    struct qdisc_skb_head q; /* [152-175] 24 bytes */
    unsigned char __padding4[208]; /* [176-383] 208 bytes */
} __attribute__((__packed__)); /* total size: 384 bytes */

struct sk_buff {
    unsigned char __padding1[16]; /* [0-15] 16 bytes */
    struct net_device * dev; /* [16-23] 8 bytes */
    struct sock * sk; /* [24-31] 8 bytes */
    unsigned char __padding2[8]; /* [32-39] 8 bytes */
    unsigned char  cb[48]; /* [40-87] 48 bytes */
    unsigned char __padding3[56]; /* [88-143] 56 bytes */
    u32 skb_iif; /* [144-147] 4 bytes */
    unsigned char __padding4[24]; /* [148-171] 24 bytes */
    __be16 protocol; /* [172-173] 2 bytes */
    u16 transport_header; /* [174-175] 2 bytes */
    u16 network_header; /* [176-177] 2 bytes */
    u16 mac_header; /* [178-179] 2 bytes */
    unsigned char __padding5[12]; /* [180-191] 12 bytes */
    void * head; /* [192-199] 8 bytes */
    unsigned char __padding6[24]; /* [200-223] 24 bytes */
} __attribute__((__packed__)); /* total size: 224 bytes */

struct sk_buff_head {
    unsigned char __padding1[16]; /* [0-15] 16 bytes */
    unsigned int qlen; /* [16-19] 4 bytes */
    unsigned char __padding2[4]; /* [20-23] 4 bytes */
} __attribute__((__packed__)); /* total size: 24 bytes */

struct socket {
    unsigned char __padding1[24]; /* [0-23] 24 bytes */
    struct sock * sk; /* [24-31] 8 bytes */
    unsigned char __padding2[96]; /* [32-127] 96 bytes */
} __attribute__((__packed__)); /* total size: 128 bytes */

struct sock {
    struct sock_common __sk_common; /* [0-135] 136 bytes */
    unsigned char __padding1[80]; /* [136-215] 80 bytes */
    struct sk_buff_head sk_receive_queue; /* [216-239] 24 bytes */
    unsigned char __padding2[104]; /* [240-343] 104 bytes */
    struct sk_buff_head sk_write_queue; /* [344-367] 24 bytes */
    unsigned char __padding3[132]; /* [368-499] 132 bytes */
    u16 sk_protocol; /* [500-501] 2 bytes */
    unsigned char __padding4[242]; /* [502-743] 242 bytes */
} __attribute__((__packed__)); /* total size: 744 bytes */

#endif /* __GENERATED_STRUCTS_H__ */