/*
 * The iodine client (client.c) talking to a malicious DNS server: client_handshake() then
 * client_tunnel() over an in-process mock UDP socket (fuzz_net.h), with every reply taken from
 * the input file.
 * Covers reply decoding (dns_decode_answer, payload_unwrap, codecs), the version / login
 * (server/client IP, MTU, netmask -> tun_setip/build_netmask) / raw-UDP / EDNS0 / codec /
 * lazy-mode / fragsize handshake replies, and downstream fragment reassembly + zlib inflate.
 *
 * File-input AFL target, run once per input: the client exit()s (errx) on several hostile
 * replies, e.g. a login reply whose MTU tun_setmtu() rejects, which is normal client behaviour
 * a libFuzzer target would report as a crash (docs/rules/common.md: exit() -> file-input).
 *
 * Input: byte 0 = config (bits 0-2 query type: NULL PRIVATE CNAME A MX SRV TXT, 7 = autodetect;
 * bit 3 raw mode; bit 4 lazy mode; bit 5 fragsize autoprobe; bits 6-7 downstream codec preset:
 * none (autodetect) / Base32 / Base64 / Base128), then records (fuzz_common.h). Each time the
 * client waits on its DNS socket and nothing is queued, the next record is delivered as a
 * reply from the resolver. kind bit 0 clear: the reply's DNS id is set to the id of the
 * client's latest query (a server that sees the query echoes it; the rest of the reply is
 * attacker data); set: delivered unchanged. kind bit 1: no reply this time (the wait times out,
 * driving the retry/ping paths). When the input is exhausted the client is stopped.
 *
 * Environment mocks (libc only, no iodine code is replaced): the socket calls (fuzz_net.h, Mayhem's
 * sandbox allows no real sockets); select() never sleeps - it
 * delivers the next record or reports a timeout; sleep() returns at once; the interface
 * ioctls tun_setip()/tun_setmtu() issue succeed as if a tun device existed; entropy is zero
 * (fuzz_common.h). The tun device is a non-blocking pipe.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include "fuzz_common.h"
#include "fuzz_net.h"

#include "src/client.h"
#include "src/common.h"
#include "src/udp.h"

static struct mock_sock *client;	/* the client's DNS socket */
static struct mock_sock *resolver;	/* the (malicious) resolver */
static int tun_pipe[2] = { -1, -1 };
static struct reader rd;
static char password[33] = "testpass";

static void tun_drain(void)
{
	char tun[4096];

	while (read(tun_pipe[0], tun, sizeof(tun)) > 0)
		;
}

int select(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds, struct timeval *tv)
{
	static uint8_t reply[64 * 1024];
	const uint8_t *pkt;
	size_t len;
	int kind, want;

	(void) nfds;
	(void) tv;
	want = rfds && FD_ISSET(client->fd, rfds);
	if (rfds)
		FD_ZERO(rfds);
	if (wfds)
		FD_ZERO(wfds);
	if (efds)
		FD_ZERO(efds);
	if (!want)
		return 0;

	tun_drain();
	if (!client->pending) {
		if (!next_record(&rd, &kind, &pkt, &len)) {
			client_stop();
			return 0;
		}
		if (kind & 2)
			return 0;	/* timeout */
		memcpy(reply, pkt, len);
		/* echo the DNS id of the client's latest query */
		if (!(kind & 1) && len >= 2)
			memcpy(reply, client->last_sent, 2);
		mock_deliver(client, resolver, reply, len);
	}
	FD_SET(client->fd, rfds);
	return 1;
}

unsigned int sleep(unsigned int seconds)
{
	(void) seconds;
	return 0;
}

int ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);
	switch (request) {
	case SIOCSIFADDR:
	case SIOCSIFDSTADDR:
	case SIOCSIFNETMASK:
	case SIOCSIFFLAGS:
	case SIOCSIFMTU:
		return 0;
	case SIOCGIFFLAGS:
		((struct ifreq *) arg)->ifr_flags = 0;
		return 0;
	}
	return (int) syscall(SYS_ioctl, fd, request, arg);
}

static const char *const qtypes[] = { "NULL", "PRIVATE", "CNAME", "A", "MX", "SRV", "TXT" };
static const char *const downencs[] = { NULL, "Base32", "Base64", "Base128" };

int main(int argc, char **argv)
{
	static uint8_t input[1 << 20];
	size_t size;
	FILE *f;
	struct net_addr resolver_addr;
	int cfg;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <input file>\n", argv[0]);
		return 2;
	}
	f = fopen(argv[1], "rb");
	if (!f) {
		perror(argv[1]);
		return 2;
	}
	size = fread(input, 1, sizeof(input), f);
	fclose(f);
	if (size < 1)
		return 0;
	cfg = input[0];
	rd.p = input + 1;
	rd.left = size - 1;

	client = mock_open(40000);
	resolver = mock_open(53);
	mock_addr(resolver, &resolver_addr.addr, &resolver_addr.addrlen);
	if (pipe(tun_pipe) != 0)
		abort();
	fcntl(tun_pipe[0], F_SETFL, O_NONBLOCK);
	fcntl(tun_pipe[1], F_SETFL, O_NONBLOCK);

	client_init();
	client_set_nameserver(&resolver_addr);
	client_set_topdomain("test.iodine.code");
	client_set_password(password);
	client_set_selecttimeout(4);
	client_set_lazymode((cfg >> 4) & 1);
	client_set_hostname_maxlen(0xFF);
	if ((cfg & 7) != 7)
		client_set_qtype((char *) qtypes[cfg & 7]);
	if (downencs[(cfg >> 6) & 3])
		client_set_downenc((char *) downencs[(cfg >> 6) & 3]);

	if (client_handshake(client->fd, (cfg >> 3) & 1, (cfg >> 5) & 1, 1000) == 0)
		client_tunnel(tun_pipe[1], client->fd);
	return 0;
}
