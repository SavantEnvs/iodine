/*
 * iodined's datagram handler, tunnel_dns(), fed UDP datagrams - the server's untrusted network
 * input - through in-process mock sockets (fuzz_net.h). Covers raw-UDP login/data/ping (raw_decode), DNS query decoding, the
 * version/login/codec/options/fragsize/ping/data commands of the tunnel protocol, the
 * downstream queue/dnscache/qmem, zlib decompression of upstream packets, NS/A/AAAA/SOA replies,
 * and query forwarding plus forwarded answers (tunnel_bind) for names outside the topdomain.
 *
 * Input: records (fuzz_common.h). kind bit 0 clear: a datagram from the tunnel client to the
 * server's DNS socket, handled with tunnel_dns(); set: a datagram from the forward target to the
 * server's bind socket, handled with tunnel_bind(). Configuration mirrors tests/thin_server.c
 * (topdomain test.iodine.code, password "testpass", 10.0.0.1/27, MTU 1130, check_ip on).
 *
 * State kept across inputs: the mock socket descriptors (their queues are reset per input) and the
 * tun pipe (drained after every datagram). The user table, forward-query cache and server
 * parameters are re-initialised for every input.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "fuzz_common.h"
#include "fuzz_net.h"

#include "src/common.h"
#include "src/fw_query.h"
#include "src/server.h"
#include "src/udp.h"
#include "src/user.h"

static struct dnsfd dns_fds = { INVALID_SOCK, INVALID_SOCK };
static struct mock_sock *srv;		/* iodined's DNS socket */
static struct mock_sock *client;	/* the tunnel client / resolver */
static struct mock_sock *bind_sock;	/* iodined's forwarding socket */
static struct mock_sock *sink;		/* the forward target (-b port) */
static int tun_pipe[2] = { -1, -1 };
static char password[33] = "testpass";

static void drain(int fd)
{
	static char buf[64 * 1024];
	while (read(fd, buf, sizeof(buf)) > 0)
		;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void) argc;
	(void) argv;

	srv = mock_open(53);
	client = mock_open(40000);
	bind_sock = mock_open(40001);
	sink = mock_open(5353);
	dns_fds.v4fd = srv->fd;
	if (pipe(tun_pipe) != 0)
		abort();
	fcntl(tun_pipe[0], F_SETFL, O_NONBLOCK);
	fcntl(tun_pipe[1], F_SETFL, O_NONBLOCK);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct server_params params;
	struct reader rd = { data, size };
	const uint8_t *pkt;
	size_t len;
	int kind;

	/* fresh server state for every input */
	mock_reset();
	fw_query_init();
	free(users);
	users = NULL;
	memset(&params, 0, sizeof(params));
	params.topdomain = "test.iodine.code";
	params.password = password;
	inet_pton(AF_INET, "10.0.0.1", &params.server_ip);
	params.netmask = 27;
	params.users = init_users(16, params.server_ip, params.netmask);
	params.check_ip = 1;
	params.tunnel_mtu = 1130;
	inet_pton(AF_INET, "10.0.0.1", &params.nameserver_ip);
	mock_addr(sink, &params.bind_addr.addr, &params.bind_addr.addrlen);
	server_init(&params);

	while (next_record(&rd, &kind, &pkt, &len)) {
		if (kind & 1) {
			mock_deliver(bind_sock, sink, pkt, len);
			tunnel_bind(bind_sock->fd, &dns_fds);
		} else {
			mock_deliver(srv, client, pkt, len);
			tunnel_dns(tun_pipe[1], srv->fd, &dns_fds, bind_sock->fd);
		}
		drain(tun_pipe[0]);
	}
	return 0;
}
