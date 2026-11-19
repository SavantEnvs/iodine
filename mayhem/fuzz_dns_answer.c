/*
 * DNS answer decoding as the iodine client does it (client.c read_dns): an untrusted UDP reply
 * from the (possibly malicious) DNS server goes through dns_decode_answer(), and for the
 * hostname/TXT record types the extracted payload is unwrapped with payload_unwrap().
 * Reaches read.c readname/readdata/readtxtbin and the base32/64/128 decoders.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "src/dns.h"
#include "src/encoding.h"
#include "src/ui.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static char out[64 * 1024];
	struct dns_msg q;
	char *pkt;
	int rv;

	/* exact-size heap copy so ASan sees any read past the datagram */
	pkt = malloc(size ? size : 1);
	if (!pkt)
		return 0;
	memcpy(pkt, data, size);

	memset(&q, 0, sizeof(q));
	rv = dns_decode_answer(out, sizeof(out), &q, pkt, size);
	if (rv > 0 && q.rtype != T_NULL && q.rtype != T_PRIVATE)
		payload_unwrap(out, rv, q.rtype);

	free(pkt);
	return 0;
}
