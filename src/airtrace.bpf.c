#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "airtrace.h"

// clang -E -target bpf -D__BPF_TRACING__ -D__TARGET_ARCH_x86 -Wall -g airtrace.bpf.c -o airtrace.i

const char kprobe_sys_msg[16] = "sys_execve";
const char kprobe_msg[16] = "do_execve";
const char fentry_msg[16] = "fentry_execve";
const char tp_msg[16] = "tp_execve";
const char tp_btf_exec_msg[16] = "tp_btf_exec";
const char raw_tp_exec_msg[16] = "raw_tp_exec";
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

static inline bool skb_l2_check(u16 header)
{
    return !header || header == (u16)~0U;
}

#define AF_INET 2         /* Internet IP Protocol 	*/
#define AF_INET6 10       /* IP version 6			*/
#define ETH_P_IP 0x0800   /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/
#define ETH_P_ARP 0x0806  /* Address Resolution packet	*/

#define MGMT_DMA_BUFFER_SIZE    1600	/*2048 */

struct elem_s
{
    unsigned char Msg[MGMT_DMA_BUFFER_SIZE];
    unsigned long Machine;
};

struct hdr_s {
    u32 frame_control;
    unsigned char dst[6];
    unsigned char src[6];
    unsigned char bssid[6];
} __attribute__((__packed__));

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

int filter_need_handle(struct hdr_s *hdr)
{
    int ret = 0;
    // unsigned char filter_mac[6] = {0xd4, 0xd7, 0xcf, 0xd1, 0x7c, 0xa9};

    pkt_args_t *pkt_filter = CONFIG();
    if (mac_eaqul(hdr->src, pkt_filter->addr))
    {
        ret = 1;
    }
    else if (mac_eaqul(hdr->dst, pkt_filter->addr))
    {
        ret = 1;
    }

    return ret;
}

struct my_pt_regs {
	unsigned int uregs[18];
};

// MiniportMMRequest
SEC("kprobe/MiniportMMRequest")
int trace_MiniportMMRequest(struct my_pt_regs *ctx)
{
    unsigned int msglen = (unsigned int)PT_REGS_PARM4(ctx);
    unsigned char *msg = (unsigned char *)PT_REGS_PARM3(ctx);
    bpf_printk("request msglen : %u\n", msglen);
    // if (msglen >= sizeof(struct hdr_s))
    // {
    //     struct hdr_s hdr;
    //     bpf_probe_read_kernel(&hdr, sizeof(hdr), msg);
    //     if (filter_need_handle(&hdr)){
    //         static struct event_t data;
    //         bpf_printk("[FRAME] to %02x:%02x:%02x:%02x:%02x:%02x\n", 
    //             hdr.src[0], hdr.src[1], hdr.src[2], hdr.src[3], hdr.src[4], hdr.src[5]);
    //         if (msglen < sizeof(data.message))
    //         {
    //             bpf_probe_read_kernel(data.message, msglen, msg);
    //             data.msglen = msglen;
    //             int send_len = offsetof(struct event_t, message) + msglen;
    //             bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, send_len);
    //         }
    //     }
    // }
    
    return 0;
}

// MlmeEnqueueForRecv
SEC("kprobe/MlmeEnqueueForRecv")
int __trace_MlmeEnqueueForRecv(struct my_pt_regs *ctx)
{
    unsigned long msglen = (unsigned long)PT_REGS_PARM4(ctx);
    unsigned char *msg = (unsigned char *)PT_REGS_PARM5(ctx);
    bpf_printk("recv msglen : %u\n", msglen);
    // if (msglen >= sizeof(struct hdr_s))
    // {
    //     struct hdr_s hdr;
    //     bpf_probe_read_kernel(&hdr, sizeof(hdr), msg);
    //     if (filter_need_handle(&hdr)){
    //         static struct event_t data;
    //         bpf_printk("[FRAME] from %02x:%02x:%02x:%02x:%02x:%02x\n", 
    //             hdr.src[0], hdr.src[1], hdr.src[2], hdr.src[3], hdr.src[4], hdr.src[5]);
    //         if (msglen < sizeof(data.message))
    //         {
    //             bpf_probe_read_kernel(data.message, msglen, msg);
    //             data.msglen = msglen;
    //             bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
    //         }
    //     }
    // }
    
    return 0;
}

SEC("kprobe/dev_hard_start_xmit")
int __trace_dev_hard_start_xmit(struct pt_regs *ctx)
{
    pkt_args_t *pkt_filter = CONFIG();
    bpf_printk("filter addr %02x:%02x:%02x:%02x:%02x:%02x\n", 
                pkt_filter->addr[0], pkt_filter->addr[1], pkt_filter->addr[2], pkt_filter->addr[3], pkt_filter->addr[4], pkt_filter->addr[5]);

}

// my_target_function
SEC("kprobe/my_target_function")
int __trace_my_target_function(struct pt_regs *ctx)
{
    pkt_args_t *pkt_filter = CONFIG();
    bpf_printk("filter addr %02x:%02x:%02x:%02x:%02x:%02x\n", 
                pkt_filter->addr[0], pkt_filter->addr[1], pkt_filter->addr[2], pkt_filter->addr[3], pkt_filter->addr[4], pkt_filter->addr[5]);

}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
