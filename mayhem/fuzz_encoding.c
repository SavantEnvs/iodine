/*
 * iodine's hostname/payload codecs (encoding.c, base32/64/64u/128). Upstream data arrives as the
 * labels of a query name and is decoded with unpack_data(); downstream data is wrapped into
 * CNAME/A/MX/SRV/TXT answers with payload_wrap() and unwrapped by the client with
 * payload_unwrap(). Byte 0 selects the codec and record type; byte 1 the hostname length limit.
 * Round trips that must be lossless are asserted.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/dns.h"
#include "src/encoding.h"

static const struct encoder *const encs[] = {
	&base32_ops, &base64_ops, &base64u_ops, &base128_ops, &raw_ops,
};
static const unsigned short qtypes[] = { T_CNAME, T_A, T_MX, T_SRV, T_TXT, T_NULL };

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static char out[64 * 1024];
	static char host[64 * 1024];
	static char wrapped[64 * 1024];
	const struct encoder *enc;
	unsigned short qtype;
	size_t len, datalen, enclen, declen;
	char *copy;
	int maxlen, r;

	if (size < 2)
		return -1;
	enc = encs[(data[0] & 0x0f) % 5];
	qtype = qtypes[(data[0] >> 4) % 6];
	maxlen = data[1];
	data += 2;
	size -= 2;

	/* 1) decode attacker-supplied hostname data (server side, unpack_data mutates it) */
	copy = malloc(size + 2);
	if (!copy)
		return 0;
	memcpy(copy, data, size);
	copy[size] = '\0';
	copy[size + 1] = '\0';
	unpack_data(out, sizeof(out), copy, size, enc);

	/* 2) build a query hostname from the bytes (client side) */
	build_hostname(host, 256, (const char *) data, size, "t.example.com", enc, maxlen);

	/* 3) codec round trip: encode then decode must give back the consumed prefix */
	if (enc != &raw_ops) {
		enclen = sizeof(host) - 1;
		memset(host, 0, sizeof(host));
		len = enc->encode(host, &enclen, data, size > 8000 ? 8000 : size);
		declen = sizeof(out) - 1;
		r = enc->decode(out, &declen, host, len);
		if ((size_t) r < enclen || memcmp(out, data, enclen) != 0) {
			fprintf(stderr, "%s round trip mismatch: %zu bytes in, %d out\n",
				enc->name, enclen, r);
			abort();
		}
	}

	/* 4) downstream wrap (server) then unwrap (client) */
	datalen = size;
	r = payload_wrap(wrapped, sizeof(wrapped), (const char *) data, &datalen, qtype, enc);
	if (r > 0)
		payload_unwrap(wrapped, r, qtype);

	/* 5) unwrap attacker-supplied answer payload directly. payload_unwrap()'s MX/SRV input is
	 * "Hname.com\0Hanother.com\0\0" (encoding.c), double-NUL terminated as
	 * dns_decode_answer() leaves it, so the copy keeps two NULs after the data. */
	memcpy(copy, data, size);
	copy[size] = copy[size + 1] = '\0';
	payload_unwrap(copy, size, qtype);

	free(copy);
	return 0;
}
