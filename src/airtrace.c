#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <stdint.h>
#include <signal.h>
#include "types.h"
#include "airtrace.h"
#include "airtrace.skel.h"
#include "dot11_type.h"

struct pcap_global_hdr_s
{
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t timezone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
} __attribute__((packed));

struct pcap_packet_hdr_s
{
    uint32_t timestamp_s;
    uint32_t timestamp_us;
    uint32_t capture_len;
    uint32_t original_len;
} __attribute__((packed));

struct pcap_radiotap_hdr_s
{
    uint8_t revision;
    uint8_t pad;
    uint16_t hdrlen;
    uint32_t present_flags;
    uint8_t flags;
    uint8_t data_rate;
    uint16_t channel_frequency;
    uint16_t channel_flags;
    int8_t antenna_signal;
    int8_t antenna_noise;
    uint16_t signal_quality;
} __attribute__((packed));

struct pcap_mypkt
{
    struct pcap_packet_hdr_s packet_hdr;
    struct pcap_radiotap_hdr_s radiotap_hdr;
} __attribute__((packed));

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}
FILE *fp = NULL;
void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct event_t *m = data;
	struct pcap_mypkt pkt;
	pkt.packet_hdr.timestamp_s = 0x5fa45360;
    pkt.packet_hdr.timestamp_us = 0;
    pkt.packet_hdr.capture_len = m->msglen + sizeof(pkt.radiotap_hdr);
    pkt.packet_hdr.original_len = m->msglen + sizeof(pkt.radiotap_hdr);
    pkt.radiotap_hdr.revision = 0;
    pkt.radiotap_hdr.pad = 0;
    pkt.radiotap_hdr.hdrlen = sizeof(pkt.radiotap_hdr);
    pkt.radiotap_hdr.present_flags = 0x000000ee;
    pkt.radiotap_hdr.flags = 0x12;
    pkt.radiotap_hdr.data_rate = 0x0c;
    pkt.radiotap_hdr.channel_frequency = 0x14b4;
    pkt.radiotap_hdr.channel_flags = 0x0140;
    pkt.radiotap_hdr.antenna_signal = -27;
    pkt.radiotap_hdr.antenna_noise = -89;
    pkt.radiotap_hdr.signal_quality = 0x0064;
	

	header_802_11_t *hdr = (header_802_11_t *)m->message;
	if (hdr->FC.Type == FC_TYPE_DATA)
	{
		pkt.packet_hdr.capture_len += 2;
		pkt.packet_hdr.original_len += 2;
		fwrite(&pkt, sizeof(pkt), 1, fp);

		u16 qos_control = 0;
		fwrite(hdr, sizeof(header_802_11_t), 1, fp);

		fwrite(&qos_control, sizeof(qos_control), 1, fp);
		fwrite(m->message + sizeof(header_802_11_t), m->msglen - sizeof(header_802_11_t), 1, fp);
		// u64 frame_check = 0;
		// fwrite(&frame_check, sizeof(frame_check), 1, fp);
	}
	else
	{
		fwrite(&pkt, sizeof(pkt), 1, fp);
		fwrite(m->message, m->msglen, 1, fp);
	}
	fflush(fp);
	printf("frame msglen %d\n", m->msglen);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("lost event\n");
}

#include <stdatomic.h>
#include <stdbool.h>

static volatile sig_atomic_t g_exit_flag = false;

void sigint_handler(int sig) {
	 g_exit_flag = true; // 设置退出标志
}

extern LIBBPF_API int bpf_map_update_elem(int fd, const void *key, const void *value,
				   __u64 flags);

#define bpf_set_config(skel, sec, value) do {		\
	int fd = bpf_map__fd(skel->maps.m_config);	\
	unsigned char buf[CONFIG_MAP_SIZE] = {};			\
	int key = 0;					\
							\
	if (fd < 0) {					\
		printf("failed to get config map: %d\n",\
		       fd);				\
		break;					\
	}						\
							\
	memcpy(buf, &value, sizeof(value));		\
	bpf_map_update_elem(fd, &key, buf, 0);		\
} while (0)


// int bpf_set_config(struct airtrace_bpf *skel, bpf_args_t *value)
// {
// 	int ret = 0;
// 	int fd = bpf_map__fd(skel->maps.m_config);	
// 	unsigned char buf[CONFIG_MAP_SIZE] = {};			
// 	int key = 0;					
							
// 	if (fd < 0) {					
// 		printf("failed to get config map: %d\n",
// 		       fd);							
// 	}						
							
// 	memcpy(buf, value, sizeof(*value));
// 	ret = bpf_map_update_elem(fd, &key, buf, 0);
// 	return ret;

// }

int main(int argc, char *argv[])
{
    struct airtrace_bpf *skel;
	// struct bpf_object_open_opts *o;
    int err;
	struct perf_buffer *pb = NULL;

	struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask); // 清空信号掩码
    sa.sa_flags = 0; // 无特殊标志

    // 注册信号处理
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction 失败");
        exit(EXIT_FAILURE);
    }


	libbpf_set_print(libbpf_print_fn);

	char log_buf[64 * 1024];
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kernel_log_buf = log_buf,
		.kernel_log_size = sizeof(log_buf),
		.kernel_log_level = 1,
	);

	skel = airtrace_bpf__open_opts(&opts);
	if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

	err = airtrace_bpf__load(skel);
	// Print the verifier log
	for (int i=0; i < sizeof(log_buf); i++) {
		if (log_buf[i] == 0 && log_buf[i+1] == 0) {
			break;
		}
		printf("%c", log_buf[i]);
	}
	
	if (err) {
		printf("Failed to load BPF object\n");
		airtrace_bpf__destroy(skel);
		return 1;
	}

	// set filter
	bpf_args_t bpf_args;
	// unsigned char filter_mac[6] = {0xd4, 0xd7, 0xcf, 0xd1, 0x7c, 0xa9};
	memset(&bpf_args, 0, sizeof(bpf_args));

	if (argc >= 3 && 0 == strcmp(argv[1], "--addr"))
	{
		sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
			&bpf_args.pkt.addr[0], &bpf_args.pkt.addr[1], &bpf_args.pkt.addr[2], 
			&bpf_args.pkt.addr[3], &bpf_args.pkt.addr[4], &bpf_args.pkt.addr[5]);
	}
	

	bpf_set_config(skel, bss, bpf_args);

	// Attach the progams to the events
	err = airtrace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		airtrace_bpf__destroy(skel);
        return 1;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		airtrace_bpf__destroy(skel);
        return 1;
	}

	// 写入文件
    fp = fopen("test.pcap", "wb");
    if (!fp)
    {
        perror("Failed to open file");
        return 1;
    }

	struct pcap_global_hdr_s global_hdr;
	global_hdr.magic = 0xa1b2c3d4;
    global_hdr.version_major = 2;
    global_hdr.version_minor = 4;
    global_hdr.timezone = 0;
    global_hdr.sigfigs = 0;
    global_hdr.snaplen = 1024;
    global_hdr.linktype = 0x7f; // 802.11 pkt
    fwrite(&global_hdr, sizeof(global_hdr), 1, fp);


	printf("begin capture...\n");
	while (true) {
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		// if (err == -EINTR) {
		// 	err = 0;
		// 	break;
		// }
		// if (err < 0) {
		// 	printf("Error polling perf buffer: %d\n", err);
		// 	break;
		// }
		if (g_exit_flag)
		{
			break;
		}
	}
	printf("end capture...\n");

    fclose(fp);

	perf_buffer__free(pb);
	airtrace_bpf__destroy(skel);
	return -err;
}
