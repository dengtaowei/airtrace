#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <argp.h>
#include "types.h"
#include "airtrace.h"
#include "airtrace.skel.h"
#include "dot11_type.h"


#define MAX_FILE_SIZE (50 * 1024 * 1024) // 50MB
// #define MAX_FILE_SIZE (512) // 50MB

static struct env {
	unsigned char filter_mac[MAX_MAC_FILTER][6];
	int mac_num;
    char file[128];
	int max_size;
} env = {
	.filter_mac = { { 0 } },
	.mac_num = 0,
	.file = "./airtrace.pcap",
	.max_size = MAX_FILE_SIZE
};


const char *argp_program_version = "airtrace 0.1";
const char *argp_program_bug_address =
	"modified from https://github.com/iovisor/bcc/tree/master/libbpf-tools";

const char argp_args_doc[] =
"Trace outstanding memory allocations\n"
"\n"
"USAGE: airtrace [-h] [-Z MAX_SIZE] [-o output file]\n"
"\n"
"";

static const struct argp_option argp_options[] = {
	{"max-size", 'Z', "MAX_SIZE", 0, "maximum capture file size"},
    {"output", 'o', "FILE", 0, "output file"},
	{"mac", 'm', "MAC_ADDR", 0, "Specify one or more MAC addresses (comma-separated)"},
	{ 0 }
};

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

static time_t cached_boot_time;

// 初始化时调用一次
void init_time_converter() {
    struct sysinfo info;
    sysinfo(&info);
    cached_boot_time = time(NULL) - info.uptime;
}

FILE *fp = NULL;
void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct event_t *m = data;
	struct pcap_mypkt pkt;
	pkt.packet_hdr.timestamp_s = m->timestamp_ns / 1000000000 + cached_boot_time;
    pkt.packet_hdr.timestamp_us = (m->timestamp_ns % 10000000000) / 1000;
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
	static int file_size = 0;

	if (file_size > env.max_size)
	{
		printf("file size %d > %d\n", file_size, env.max_size);
		return;
	}
	

	header_802_11_t *hdr = (header_802_11_t *)m->message;
	if (hdr->FC.Type == FC_TYPE_DATA)
	{
		pkt.packet_hdr.capture_len += 2;
		pkt.packet_hdr.original_len += 2;
		fwrite(&pkt, sizeof(pkt), 1, fp);
		file_size += sizeof(pkt);

		u16 qos_control = 0;
		fwrite(hdr, sizeof(header_802_11_t), 1, fp);
		file_size += sizeof(header_802_11_t);

		fwrite(&qos_control, sizeof(qos_control), 1, fp);
		file_size += sizeof(qos_control);
		fwrite(m->message + sizeof(header_802_11_t), m->msglen - sizeof(header_802_11_t), 1, fp);
		file_size += m->msglen;
		// u64 frame_check = 0;
		// fwrite(&frame_check, sizeof(frame_check), 1, fp);
	}
	else
	{
		fwrite(&pkt, sizeof(pkt), 1, fp);
		file_size += sizeof(pkt);
		fwrite(m->message, m->msglen, 1, fp);
		file_size += m->msglen;
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

long argp_parse_long(int key, const char *arg, struct argp_state *state)
{
	errno = 0;
	const long temp = strtol(arg, NULL, 10);
	if (errno || temp <= 0) {
		fprintf(stderr, "error arg:%c %s\n", (char)key, arg);
		argp_usage(state);
	}

	return temp;
}

static void parse_mac_filter(struct env *env, char *arg)
{
	 char *token = strtok(arg, ",");
	while (token) {
		if (env->mac_num >= sizeof(env->filter_mac) / sizeof(env->filter_mac[0]))
		{
			return;
		}

		if (strlen(token) == 17 && strchr(token, ':')) {
			sscanf(token, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
               &env->filter_mac[env->mac_num][0], &env->filter_mac[env->mac_num][1], 
			   &env->filter_mac[env->mac_num][2], &env->filter_mac[env->mac_num][3], 
			   &env->filter_mac[env->mac_num][4], &env->filter_mac[env->mac_num][5]);
			env->mac_num++;
		} else {
			fprintf(stderr, "Invalid MAC format: %s\n", token);
			return;
		}
		token = strtok(NULL, ",");
	}
}

error_t argp_parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'o':
		// env.min_age_ns = 1e6 * atoi(arg);
		snprintf(env.file, sizeof(env.file), "%s", arg);
		break;
	case 'Z':
		env.max_size = atoi(arg);
		break;
	case 'm':
		parse_mac_filter(&env, arg);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

#include <sys/resource.h>

int liberate_l()
{
	struct rlimit lim = {RLIM_INFINITY, RLIM_INFINITY};
	return setrlimit(RLIMIT_MEMLOCK, &lim);
}

int main(int argc, char *argv[])
{
    struct airtrace_bpf *skel;
	// struct bpf_object_open_opts *o;
    int err;
	struct perf_buffer *pb = NULL;

	static const struct argp argp = {
		.options = argp_options,
		.parser = argp_parse_arg,
		.doc = argp_args_doc,
	};

    // parse command line args to env settings
	if (argp_parse(&argp, argc, argv, 0, NULL, NULL)) {
		perror("failed to parse args");
        exit(EXIT_FAILURE);
	}

	struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask); // 清空信号掩码
    sa.sa_flags = 0; // 无特殊标志

    // 注册信号处理
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction 失败");
        exit(EXIT_FAILURE);
    }

	init_time_converter();


	libbpf_set_print(libbpf_print_fn);

	char log_buf[512 * 1024];
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kernel_log_buf = log_buf,
		.kernel_log_size = sizeof(log_buf),
		.kernel_log_level = 1,
	);

	liberate_l();

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
	memcpy(bpf_args.pkt.addr, env.filter_mac, sizeof(bpf_args.pkt.addr));
	bpf_args.pkt.mac_num = env.mac_num;

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
    fp = fopen(env.file, "wb");
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
