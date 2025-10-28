// #include "vmlinux.h"
#include "ktypes.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "airtrace.h"
#include "dot11_type.h"

// clang -E -target bpf -D__BPF_TRACING__ -D__TARGET_ARCH_x86 -Wall -g airtrace.bpf.c -o airtrace.i

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, CONFIG_MAP_SIZE);
	__uint(max_entries, 1);
} m_config SEC(".maps");

typedef struct
{
    void *data;
    u16 mac_header;
    u16 network_header;
} parse_ctx_t;


#define MGMT_DMA_BUFFER_SIZE    1600	/*2048 */

struct elem_s
{
    unsigned char Msg[MGMT_DMA_BUFFER_SIZE];
    unsigned long Machine;
};

#define AUTH_FSM 2
#define ASSOC_FSM 1
#define WPA_STATE_MACHINE 23

// SEC("kprobe/StateMachinePerformAction")
// int trace_StateMachinePerformAction(struct pt_regs *ctx)
// {

//     // char comm[16];
//     // u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
//     // bpf_get_current_comm(comm, sizeof(comm));

//     // bpf_printk("pid: %u, comm: %s\n", pid, comm);

//     struct elem_s *elem = (struct elem_s *)PT_REGS_PARM3(ctx);
//     unsigned long Machine;
//     bpf_probe_read_kernel(&Machine, sizeof(Machine), ((char *)elem) + 2304);
//     if (AUTH_FSM == Machine)
//     {
//         struct hdr_s hdr;
//         bpf_probe_read_kernel(&hdr, sizeof(hdr), ((char *)elem) + 0);
//         bpf_printk("[Machine] %lu - auth from %02x:%02x:%02x:%02x:%02x:%02x\n", Machine, 
//             hdr.src[0], hdr.src[1], hdr.src[2], hdr.src[3], hdr.src[4], hdr.src[5]);
//     }
//     else if (ASSOC_FSM == Machine)
//     {
//         struct hdr_s hdr;
//         bpf_probe_read_kernel(&hdr, sizeof(hdr), ((char *)elem) + 0);
//         bpf_printk("[Machine] %lu - assoc from %02x:%02x:%02x:%02x:%02x:%02x\n", Machine, 
//             hdr.src[0], hdr.src[1], hdr.src[2], hdr.src[3], hdr.src[4], hdr.src[5]);
//     }
//     else if (WPA_STATE_MACHINE == Machine)
//     {
//         struct hdr_s hdr;
//         bpf_probe_read_kernel(&hdr, sizeof(hdr), ((char *)elem) + 0);
//         bpf_printk("[Machine] %lu - wpa from %02x:%02x:%02x:%02x:%02x:%02x\n", Machine, 
//             hdr.src[0], hdr.src[1], hdr.src[2], hdr.src[3], hdr.src[4], hdr.src[5]);
//     }
//     return 0;
// }

// // MacTableInsertEntry
// SEC("kprobe/MacTableInsertEntry")
// int trace_MacTableInsertEntry(struct pt_regs *ctx)
// {
//     unsigned char *addr = (unsigned char *)PT_REGS_PARM2(ctx);
//     unsigned char src[6];
//     bpf_probe_read_kernel(src, sizeof(src), addr);
//     bpf_printk("[insert entry] %02x:%02x:%02x:%02x:%02x:%02x\n", 
//             src[0], src[1], src[2], src[3], src[4], src[5]);
//     return 0;
// }

// // MacTableDeleteEntry
// SEC("kprobe/MacTableDeleteEntry")
// int trace_MacTableDeleteEntry(struct pt_regs *ctx)
// {
//     unsigned char *addr = (unsigned char *)PT_REGS_PARM3(ctx);
//     unsigned char src[6];
//     bpf_probe_read_kernel(src, sizeof(src), addr);
//     bpf_printk("[delete entry] %02x:%02x:%02x:%02x:%02x:%02x\n", 
//             src[0], src[1], src[2], src[3], src[4], src[5]);
//     return 0;
// }

// // PeerPairMsg2Action
// SEC("kprobe/PeerPairMsg2Action")
// int trace_PeerPairMsg2Action(struct pt_regs *ctx)
// {
//     struct elem_s *elem = (struct elem_s *)PT_REGS_PARM2(ctx);
//     struct hdr_s hdr;
//     bpf_probe_read_kernel(&hdr, sizeof(hdr), elem->Msg);
//     bpf_printk("[EAPOL ACTION] eapol 2 from %02x:%02x:%02x:%02x:%02x:%02x\n", 
//             hdr.src[0], hdr.src[1], hdr.src[2], hdr.src[3], hdr.src[4], hdr.src[5]);
//     return 0;
// }

// // PeerPairMsg4Action
// SEC("kprobe/PeerPairMsg4Action")
// int trace_PeerPairMsg4Action(struct pt_regs *ctx)
// {
//     struct elem_s *elem = (struct elem_s *)PT_REGS_PARM2(ctx);
//     struct hdr_s hdr;
//     bpf_probe_read_kernel(&hdr, sizeof(hdr), elem->Msg);
//     bpf_printk("[EAPOL ACTION] eapol 4 from %02x:%02x:%02x:%02x:%02x:%02x\n", 
//             hdr.src[0], hdr.src[1], hdr.src[2], hdr.src[3], hdr.src[4], hdr.src[5]);
//     return 0;
// }

// SEC("kretprobe/WpaMessageSanity")
// int BPF_KRETPROBE(WpaMessageSanity_exit, unsigned char ret) {
    
//     // 打印返回值（0 或 1）
//     bpf_printk("WpaMessageSanity returned: %u \n", ret);
    
//     // 可选：统计返回值分布
//     if (ret == 0) {
//         bpf_printk("Validation failed msg 2 maybe wrong password\n");
//     } else if (ret == 1) {
//         bpf_printk("Validation passed msg 2\n");
//     }

//     return 0;
// }

// // MlmeDeAuthAction
// SEC("kprobe/MlmeDeAuthAction")
// int trace_MlmeDeAuthAction(struct pt_regs *ctx)
// {
//     unsigned short reason = (unsigned short)PT_REGS_PARM3(ctx);

//     bpf_printk("[DEAUTH ACTION] reason %u\n", reason);
//     return 0;
// }

// // MgtMacHeaderInit
// SEC("kprobe/MgtMacHeaderInit")
// int trace_MgtMacHeaderInit(struct pt_regs *ctx)
// {
//     unsigned char type = (unsigned short)PT_REGS_PARM3(ctx);
//     unsigned char *addr = (unsigned char *)PT_REGS_PARM5(ctx);

//     if (12 == type)
//     {
//         unsigned char tmp[6];
//         bpf_probe_read_kernel(tmp, sizeof(tmp), addr);
//         bpf_printk("[FRAME] deauth to %02x:%02x:%02x:%02x:%02x:%02x\n", 
//             tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]);
//     }
//     return 0;
// }

int mac_eaqul(unsigned char *mac1, unsigned char *mac2)
{
    int ret = 1;
    for (int i = 0; i < 6; i++)
    {
        if (mac1[i] != mac2[i])
        {
            ret = 0;
            break;
        }
    }
    return ret;
}

#define CONFIG() ({						\
	int _key = 0;						\
	void * _v = bpf_map_lookup_elem(&m_config, &_key);	\
	if (!_v)						\
		return 0; /* this can't happen */		\
	(pkt_args_t *)_v;					\
})

int filter_need_handle(header_802_11_t *hdr)
{
    int ret = 0;
    // unsigned char filter_mac[6] = {0xd4, 0xd7, 0xcf, 0xd1, 0x7c, 0xa9};

    pkt_args_t *pkt_filter = CONFIG();

    for (int i = 0; i < pkt_filter->mac_num && i < MAX_MAC_FILTER; i++)
    {
        if (0 == __builtin_memcmp(hdr->Src, pkt_filter->addr[i], 6))
        {
            ret = 1;
            break;
        }
        else if (0 == __builtin_memcmp(hdr->Dst, pkt_filter->addr[i], 6))
        {
            ret = 1;
            break;
        }
    }

    return ret;
}

int filter_need_handle_802_3(struct ethhdr *hdr)
{
    int ret = 0;
    // unsigned char filter_mac[6] = {0xd4, 0xd7, 0xcf, 0xd1, 0x7c, 0xa9};

    pkt_args_t *pkt_filter = CONFIG();

    for (int i = 0; i < pkt_filter->mac_num && i < MAX_MAC_FILTER; i++)
    {
        if (0 == __builtin_memcmp(hdr->h_dest, pkt_filter->addr[i], 6))
        {
            ret = 1;
            break;
        }
        else if (0 == __builtin_memcmp(hdr->h_source, pkt_filter->addr[i], 6))
        {
            ret = 1;
            break;
        }
    }

    return ret;
}
// #define BPF_PROBE_READ(src, a, ...) ({					    \
// 	___type((src), a, ##__VA_ARGS__) __r;				    \
// 	BPF_PROBE_READ_INTO(&__r, (src), a, ##__VA_ARGS__);		    \
// 	__r;								    \
// })

// u32 PT_REGS_PARM5_ARM(struct my_pt_regs *ctx)
// {
//     u32 sp = PT_REGS_SP(ctx);
//     u32 arg5;
//     bpf_probe_read_kernel(&arg5, sizeof(arg5), (void *)(sp + 0x0));
// }
#if defined(__TARGET_ARCH_arm)
#define PT_REGS_PARM5_ARM(ctx) ({\
    u32 sp = (u32)PT_REGS_SP(ctx); \
    u32 arg5; \
    bpf_probe_read_kernel(&arg5, sizeof(arg5), (sp + 0x0)); \
    arg5; \
})

#define PT_REGS_PARM6_ARM(ctx) ({\
    u32 sp = (u32)PT_REGS_SP(ctx); \
    u32 arg6; \
    bpf_probe_read_kernel(&arg6, sizeof(arg6), (sp + 0x4)); \
    arg6; \
})
#endif

#define pt_regs_param_0 PT_REGS_PARM1
#define pt_regs_param_1 PT_REGS_PARM2
#define pt_regs_param_2 PT_REGS_PARM3
#define pt_regs_param_3 PT_REGS_PARM4
#if defined(__TARGET_ARCH_arm)
// arm32 前四个参数使用R0-R3寄存器，从第五个开始使用栈传递
#define pt_regs_param_4 PT_REGS_PARM5_ARM
#define pt_regs_param_5 PT_REGS_PARM6_ARM
#else
#define pt_regs_param_4 PT_REGS_PARM5
#endif

#if defined(__TARGET_ARCH_arm)
#define ctx_get_arg(ctx, index) (u32)pt_regs_param_##index((struct my_pt_regs*)ctx)
#else
#define ctx_get_arg(ctx, index) (void *)pt_regs_param_##index((struct pt_regs*)ctx)
#endif

// MiniportMMRequest
SEC("kprobe/MiniportMMRequest")
int trace_MiniportMMRequest(struct pt_regs *ctx)
{
    unsigned int msglen = (unsigned int)ctx_get_arg(ctx, 3);
    unsigned char *msg = (unsigned char *)ctx_get_arg(ctx, 2);
    // bpf_printk("request msglen : %u\n", msglen);
    // for (int i = 0; i < 4; i++)
    // {
    //     bpf_printk("arg%d = %x\n", i, ctx->uregs[i]);
    // }
    if (msglen >= sizeof(header_802_11_t))
    {
        header_802_11_t hdr;
        bpf_probe_read_kernel(&hdr, sizeof(hdr), msg);
        if (filter_need_handle(&hdr)){
            static struct event_t data;
            bpf_printk("[FRAME] to %02x:%02x:%02x:%02x:%02x:%02x\n", 
                hdr.Src[0], hdr.Src[1], hdr.Src[2], hdr.Src[3], hdr.Src[4], hdr.Src[5]);
            if (msglen < sizeof(data.message))
            {
                bpf_probe_read_kernel(data.message, msglen, msg);
                data.msglen = msglen;
                data.timestamp_ns = bpf_ktime_get_ns();
                int send_len = offsetof(struct event_t, message) + msglen;
                bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, send_len);
            }
        }
    }
    
    return 0;
}

// MlmeEnqueueForRecv
SEC("kprobe/MlmeEnqueueForRecv")
int __trace_MlmeEnqueueForRecv(struct pt_regs *ctx)
{
    unsigned long msglen = (unsigned long)ctx_get_arg(ctx, 3);
    unsigned char *msg = (unsigned char *)ctx_get_arg(ctx, 4);
    // bpf_printk("recv msglen : %u\n", msglen);
    // bpf_printk("recv msg : %p\n", msg);
    // for (int i = 0; i < 8; i++)
    // {
    //     bpf_printk("arg%d = %x\n", i, ctx->uregs[i]);
    // }
    
    if (msglen >= sizeof(header_802_11_t))
    {
        header_802_11_t hdr;
        bpf_probe_read_kernel(&hdr, sizeof(hdr), msg);
        if (filter_need_handle(&hdr)){
            static struct event_t data;
            bpf_printk("[FRAME] from %02x:%02x:%02x:%02x:%02x:%02x\n", 
                hdr.Src[0], hdr.Src[1], hdr.Src[2], hdr.Src[3], hdr.Src[4], hdr.Src[5]);
            if (msglen < sizeof(data.message))
            {
                bpf_probe_read_kernel(data.message, msglen, msg);
                data.msglen = msglen;
                data.timestamp_ns = bpf_ktime_get_ns();
                bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
            }
        }
    }
    
    return 0;
}
#if defined(__TARGET_ARCH_arm)
// RTMPToWirelessSta
SEC("kprobe/RTMPToWirelessSta")
int __trace_RTMPToWirelessSta(struct pt_regs *ctx)
{
    unsigned char *hdr_802_3 = (unsigned char *)ctx_get_arg(ctx, 2);
    unsigned int hdr_len = (unsigned int)ctx_get_arg(ctx, 3);
    unsigned char *data_in = (unsigned char *)ctx_get_arg(ctx, 4);
    unsigned int date_len = (unsigned int)ctx_get_arg(ctx, 5);
    static struct event_t data;
    // bpf_printk("recv hdr_len : %u\n", hdr_len);
    // bpf_printk("recv hdr_802_3 : %p\n", hdr_802_3);
    // bpf_printk("recv date_len : %u\n", date_len);
    // bpf_printk("recv data : %p\n", data);
    // for (int i = 0; i < 8; i++)
    // {
    //     bpf_printk("arg%d = %x\n", i, ctx->uregs[i]);
    // }
    if (!hdr_802_3 || !data_in || !hdr_len || !date_len)
    {
        bpf_printk("dtwdebug wrong eapol packet\n");
        return 0;
    }
    unsigned char hdr_802_3_local[14];
    bpf_probe_read_kernel(hdr_802_3_local, sizeof(hdr_802_3_local), hdr_802_3);
    if (hdr_len >= 14 && hdr_802_3_local[12] == 0x88 && hdr_802_3_local[13] == 0x8e && 
        date_len + sizeof(header_802_11_t) + 8 < 2048)
    {
        header_802_11_t *hdr = (header_802_11_t *)data.message;
        hdr->FC.Type = FC_TYPE_DATA;
        hdr->FC.SubType = SUBTYPE_QDATA;
        hdr->FC.FrDs = 1;
        bpf_probe_read_kernel(hdr->Dst, 6, hdr_802_3 + 0);
        bpf_probe_read_kernel(hdr->Src, 6, hdr_802_3 + 6);
        bpf_probe_read_kernel(hdr->Bssid, 6, hdr_802_3 + 6);
        data.msglen = sizeof(header_802_11_t);

        // data.message[data.msglen] = 0;  // add qos control userspace
        // data.msglen += 1;
        // data.message[data.msglen] = 0;
        // data.msglen += 1;

        data.message[data.msglen] = 0xaa;
        data.msglen += 1;
        data.message[data.msglen] = 0xaa;
        data.msglen += 1;
        data.message[data.msglen] = 0x03;
        data.msglen += 1;
        data.message[data.msglen] = 0x00;
        data.msglen += 1;
        data.message[data.msglen] = 0x00;
        data.msglen += 1;
        data.message[data.msglen] = 0x00;
        data.msglen += 1;
        data.message[data.msglen] = 0x88;
        data.msglen += 1;
        data.message[data.msglen] = 0x8e;
        data.msglen += 1;
        // unsigned char llc[8] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e};
        // bpf_probe_read_kernel(data.message + data.msglen, llc, sizeof(llc));
        // data.msglen += sizeof(llc);

        bpf_probe_read_kernel(data.message + data.msglen, date_len, data_in);
        data.msglen += date_len;
        data.timestamp_ns = bpf_ktime_get_ns();
        bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));

    }
    
    return 0;
}


#elif defined(__TARGET_ARCH_arm64)
// struct sk_buff: 416
// struct sk_buff::dev             offset =   16, size =    8
// struct sk_buff::sk              offset =   24, size =    8
// struct sk_buff::cb              offset =   40, size =   48
// struct sk_buff::skb_iif         offset =  144, size =    4
// struct sk_buff::protocol        offset =  172, size =    2
// struct sk_buff::transport_header offset =  174, size =    2
// struct sk_buff::network_header  offset =  176, size =    2
// struct sk_buff::mac_header      offset =  178, size =    2
// struct sk_buff::head            offset =  384, size =    8
// struct sk_buff::len             offset =  112, size =    4
// struct sk_buff::data            offset =  392, size =    8
#define SKB_MAC_HEADER_OFFSET 178
#define SKB_HEAD_OFFSET 384
#define SKB_NETWORK_HEADER_OFFSET 176
#define SKB_DATA_OFFSET 392
#define SKB_LEN_OFFSET 112
struct my_arphdr {
	u16 hw_type;       // 硬件类型 (1 for Ethernet)
    u16 proto_type;    // 协议类型 (0x0800 for IPv4)
    u8 hw_len;         // 硬件地址长度 (6 for MAC)
    u8 proto_len;      // 协议地址长度 (4 for IPv4)
    u16 opcode;        // 操作码 (1 for ARP Request)
    u8 sender_mac[6];  // 发送方MAC
    u8 sender_ip[4];   // 发送方IP
    u8 target_mac[6];  // 目标MAC (00:00:00:00:00:00)
    u8 target_ip[4];   // 目标IP
}__attribute__((__packed__));
// send_data_pkt
SEC("kprobe/send_data_pkt")
int __trace_send_data_pkt(struct pt_regs *ctx)
{
    void* skb = (void *)ctx_get_arg(ctx, 2);
	// u16 mac_header;
	// u16 network_header;
	// unsigned char *head;
    unsigned char *data;
    unsigned int len;
    static struct event_t event;

    bpf_probe_read_kernel(&len, sizeof(len), skb + SKB_LEN_OFFSET);

	bpf_probe_read_kernel(&data, sizeof(data), skb + SKB_DATA_OFFSET);

	if (len < sizeof(struct ethhdr))
	{
		return 0;
	}

    struct ethhdr eth_header;
	bpf_probe_read_kernel(&eth_header, sizeof(eth_header), data);
    if (eth_header.h_proto != 0x8e88)
    {
        return 0;
    }

    if (!filter_need_handle_802_3(&eth_header))
    {
        return 0;
    }

    // bpf_printk("dtwdebug error proto: 0x%x, len = %d, buffer %d", eth_header.h_proto, len, sizeof(event.message) - 24 - 8 + 14);


	header_802_11_t *hdr = (header_802_11_t *)event.message;

    if (len < sizeof(event.message) - 24 - 8 + 14 && len - 14 > 0)
    {
        bpf_probe_read_kernel(event.message + 24 + 8 - 14, len, data);
        event.msglen += (len - 14);
    }

    hdr->FC.Type = FC_TYPE_DATA;
    hdr->FC.SubType = SUBTYPE_QDATA;
    hdr->FC.FrDs = 1;
    bpf_probe_read_kernel(hdr->Dst, 6, eth_header.h_dest);
    bpf_probe_read_kernel(hdr->Src, 6, eth_header.h_source);
    bpf_probe_read_kernel(hdr->Bssid, 6, eth_header.h_source);
    event.msglen += sizeof(header_802_11_t);

    // data.message[data.msglen] = 0;  // add qos control userspace
    // data.msglen += 1;
    // data.message[data.msglen] = 0;
    // data.msglen += 1;

    event.message[sizeof(header_802_11_t) + 0] = 0xaa;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 1] = 0xaa;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 2] = 0x03;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 3] = 0x00;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 4] = 0x00;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 5] = 0x00;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 6] = 0x88;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 7] = 0x8e;
    event.msglen += 1;
    // unsigned char llc[8] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e};
    // bpf_probe_read_kernel(data.message + data.msglen, llc, sizeof(llc));
    // data.msglen += sizeof(llc);
    event.timestamp_ns = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("kprobe/RtmpOsPktRcvHandle")
int __trace_RtmpOsPktRcvHandle(struct pt_regs *ctx)
{
    void* skb = (void *)ctx_get_arg(ctx, 0);

    u16 mac_header;
	u16 network_header;
	unsigned char *head;

    unsigned char *data;
    unsigned int len;
    static struct event_t event;

    bpf_probe_read_kernel(&mac_header, sizeof(mac_header), skb + SKB_MAC_HEADER_OFFSET);
    bpf_probe_read_kernel(&network_header, sizeof(network_header), skb + SKB_NETWORK_HEADER_OFFSET);
    bpf_probe_read_kernel(&head, sizeof(head), skb + SKB_HEAD_OFFSET);

    bpf_probe_read_kernel(&len, sizeof(len), skb + SKB_LEN_OFFSET);

	bpf_probe_read_kernel(&data, sizeof(data), skb + SKB_DATA_OFFSET);

	if (len < sizeof(struct ethhdr))
	{
		return 0;
	}

    struct ethhdr eth_header;
	bpf_probe_read_kernel(&eth_header, sizeof(eth_header), head + mac_header);

    if (eth_header.h_proto != 0x0008)  // ipv4
    {
        return 0;
    }

    if (!filter_need_handle_802_3(&eth_header))
    {
        return 0;
    }

    // bpf_printk("error proto 0x%x, %02x:%02x:%02x:%02x:%02x:%02x", eth_header.h_proto, 
    //     eth_header.h_source[0], eth_header.h_source[1], eth_header.h_source[2], 
    //     eth_header.h_source[3], eth_header.h_source[4], eth_header.h_source[5]);
    struct iphdr ip_header;
    bpf_probe_read_kernel(&ip_header, sizeof(ip_header), head + mac_header + sizeof(struct ethhdr));
    // bpf_printk("ipv4 ver %d, len %d, protocol %d", ip_header.version, ip_header.ihl, ip_header.protocol);

    if (ip_header.ihl != 5 || ip_header.protocol != 17)  // not udp
    {
        return 0;
    }

    struct udphdr udp_header;
    bpf_probe_read_kernel(&udp_header, sizeof(udp_header), head + mac_header + sizeof(struct ethhdr) + sizeof(struct iphdr));
    // bpf_printk("udp src port %d, dst port %d, len %d", bpf_ntohs(udp_header.source), bpf_ntohs(udp_header.dest), udp_header.len);
    if (bpf_ntohs(udp_header.source) != 68 || bpf_ntohs(udp_header.dest) != 67)
    {
        return 0;
    }
    bpf_printk("udp src port %d, dst port %d, udplen %d, len %d", bpf_ntohs(udp_header.source), bpf_ntohs(udp_header.dest), bpf_ntohs(udp_header.len), len);
    
    bpf_printk("head %p, data %p, data - head %d, mac_header %d, network_header %d, ", head, data, data - head, mac_header, network_header);

    header_802_11_t *hdr = (header_802_11_t *)event.message;

    u16 udp_len = bpf_ntohs(udp_header.len); // 确保非负

    if (sizeof(struct ethhdr) + sizeof(struct iphdr) + udp_len < sizeof(event.message) - 24 - 8 + 14 && sizeof(struct ethhdr) + sizeof(struct iphdr) + udp_len - 14 > 0)
    {
        bpf_probe_read_kernel(event.message + 24 + 8 - 14, sizeof(struct ethhdr) + sizeof(struct iphdr) + udp_len, head + mac_header);
        event.msglen += (sizeof(struct ethhdr) + sizeof(struct iphdr) + udp_len - 14);
    }


    hdr->FC.Type = FC_TYPE_DATA;
    hdr->FC.SubType = SUBTYPE_QDATA;
    hdr->FC.FrDs = 1;
    bpf_probe_read_kernel(hdr->Dst, 6, eth_header.h_dest);
    bpf_probe_read_kernel(hdr->Src, 6, eth_header.h_source);
    bpf_probe_read_kernel(hdr->Bssid, 6, eth_header.h_source);
    event.msglen += sizeof(header_802_11_t);

    event.message[sizeof(header_802_11_t) + 0] = 0xaa;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 1] = 0xaa;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 2] = 0x03;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 3] = 0x00;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 4] = 0x00;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 5] = 0x00;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 6] = 0x08;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 7] = 0x00;
    event.msglen += 1;

    event.timestamp_ns = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;

}

SEC("kprobe/rt28xx_send_packets")
int __trace_rt28xx_send_packets(struct pt_regs *ctx)
{
    void* skb = (void *)ctx_get_arg(ctx, 0);

    u16 mac_header;
	u16 network_header;
	unsigned char *head;

    unsigned char *data;
    unsigned int len;
    static struct event_t event;

    bpf_probe_read_kernel(&mac_header, sizeof(mac_header), skb + SKB_MAC_HEADER_OFFSET);
    bpf_probe_read_kernel(&network_header, sizeof(network_header), skb + SKB_NETWORK_HEADER_OFFSET);
    bpf_probe_read_kernel(&head, sizeof(head), skb + SKB_HEAD_OFFSET);

    bpf_probe_read_kernel(&len, sizeof(len), skb + SKB_LEN_OFFSET);

	bpf_probe_read_kernel(&data, sizeof(data), skb + SKB_DATA_OFFSET);

	if (len < sizeof(struct ethhdr))
	{
		return 0;
	}

    struct ethhdr eth_header;
	bpf_probe_read_kernel(&eth_header, sizeof(eth_header), head + mac_header);

    if (eth_header.h_proto != 0x0008)  // ipv4
    {
        return 0;
    }

    if (!filter_need_handle_802_3(&eth_header))
    {
        return 0;
    }

    // bpf_printk("error proto 0x%x, %02x:%02x:%02x:%02x:%02x:%02x", eth_header.h_proto, 
    //     eth_header.h_source[0], eth_header.h_source[1], eth_header.h_source[2], 
    //     eth_header.h_source[3], eth_header.h_source[4], eth_header.h_source[5]);
    struct iphdr ip_header;
    bpf_probe_read_kernel(&ip_header, sizeof(ip_header), head + mac_header + sizeof(struct ethhdr));
    // bpf_printk("ipv4 ver %d, len %d, protocol %d", ip_header.version, ip_header.ihl, ip_header.protocol);

    if (ip_header.ihl != 5 || ip_header.protocol != 17)  // not udp
    {
        return 0;
    }

    struct udphdr udp_header;
    bpf_probe_read_kernel(&udp_header, sizeof(udp_header), head + mac_header + sizeof(struct ethhdr) + sizeof(struct iphdr));
    // bpf_printk("udp src port %d, dst port %d, len %d", bpf_ntohs(udp_header.source), bpf_ntohs(udp_header.dest), udp_header.len);
    if (bpf_ntohs(udp_header.source) != 67 || bpf_ntohs(udp_header.dest) != 68)
    {
        return 0;
    }
    bpf_printk("udp src port %d, dst port %d, udplen %d, len %d", bpf_ntohs(udp_header.source), bpf_ntohs(udp_header.dest), bpf_ntohs(udp_header.len), len);
    
    bpf_printk("head %p, data %p, data - head %d, mac_header %d, network_header %d, ", head, data, data - head, mac_header, network_header);

    header_802_11_t *hdr = (header_802_11_t *)event.message;

    u16 udp_len = bpf_ntohs(udp_header.len); // 确保非负

    if (sizeof(struct ethhdr) + sizeof(struct iphdr) + udp_len < sizeof(event.message) - 24 - 8 + 14 && sizeof(struct ethhdr) + sizeof(struct iphdr) + udp_len - 14 > 0)
    {
        bpf_probe_read_kernel(event.message + 24 + 8 - 14, sizeof(struct ethhdr) + sizeof(struct iphdr) + udp_len, head + mac_header);
        event.msglen += (sizeof(struct ethhdr) + sizeof(struct iphdr) + udp_len - 14);
    }


    hdr->FC.Type = FC_TYPE_DATA;
    hdr->FC.SubType = SUBTYPE_QDATA;
    hdr->FC.FrDs = 1;
    bpf_probe_read_kernel(hdr->Dst, 6, eth_header.h_dest);
    bpf_probe_read_kernel(hdr->Src, 6, eth_header.h_source);
    bpf_probe_read_kernel(hdr->Bssid, 6, eth_header.h_source);
    event.msglen += sizeof(header_802_11_t);

    event.message[sizeof(header_802_11_t) + 0] = 0xaa;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 1] = 0xaa;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 2] = 0x03;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 3] = 0x00;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 4] = 0x00;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 5] = 0x00;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 6] = 0x08;
    event.msglen += 1;
    event.message[sizeof(header_802_11_t) + 7] = 0x00;
    event.msglen += 1;

    event.timestamp_ns = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

#endif

// SEC("kprobe/dev_hard_start_xmit")
// int __trace_dev_hard_start_xmit(struct pt_regs *ctx)
// {
//     pkt_args_t *pkt_filter = CONFIG();
//     bpf_printk("filter addr %02x:%02x:%02x:%02x:%02x:%02x\n", 
//                 pkt_filter->addr[0], pkt_filter->addr[1], pkt_filter->addr[2], pkt_filter->addr[3], pkt_filter->addr[4], pkt_filter->addr[5]);

// }

// my_target_function
// SEC("kprobe/my_target_function")
// int __trace_my_target_function(struct pt_regs *ctx)
// {
//     pkt_args_t *pkt_filter = CONFIG();
//     bpf_printk("filter addr %02x:%02x:%02x:%02x:%02x:%02x\n", 
//                 pkt_filter->addr[0], pkt_filter->addr[1], pkt_filter->addr[2], pkt_filter->addr[3], pkt_filter->addr[4], pkt_filter->addr[5]);

// }

char LICENSE[] SEC("license") = "Dual BSD/GPL";
