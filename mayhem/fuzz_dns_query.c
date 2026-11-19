/*
 * DNS query decoding as iodined does it (server.c tunnel_dns): an untrusted query datagram goes
 * through dns_decode_query() and query_datalen(); the decoded struct dns_msg is then fed to the
 * response encoders the server answers with (data/forward, NS, A/AAAA, SOA).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "src/common.h"
#include "src/dns.h"

static const char topdomain[] = "test.iodine.code";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static char out[64 * 1024];
	struct sockaddr_storage ss;
	struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &ss;
	struct dns_msg q;
	char *pkt;
	int domain_len;

	pkt = malloc(size ? size : 1);
	if (!pkt)
		return 0;
	memcpy(pkt, data, size);

	memset(&q, 0, sizeof(q));
	if (dns_decode_query(&q, pkt, size) > 0) {
		domain_len = query_datalen(q.name, topdomain);

		/* answer carrying data, and a forwarded query (server.c write_dns/forward_query) */
		dns_encode(out, sizeof(out), &q, QR_ANSWER, q.name, strlen(q.name));
		dns_encode(out, sizeof(out), &q, QR_QUERY, q.name, strlen(q.name));

		memset(&ss, 0, sizeof(ss));
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (domain_len >= 0)
			dns_encode_ns_response(out, sizeof(out), &q, domain_len,
					       (struct sockaddr *) &ss);
		dns_encode_standard_response(out, sizeof(out), &q, (struct sockaddr *) &ss);

		memset(&ss, 0, sizeof(ss));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = in6addr_loopback;
		dns_encode_standard_response(out, sizeof(out), &q, (struct sockaddr *) &ss);

		dns_encode_soa(out, sizeof(out), &q, topdomain, NOERROR);
	}

	free(pkt);
	return 0;
}
