/*
 * Shared harness helpers: the input framing for multi-datagram targets and a deterministic
 * entropy source.
 *
 * Input framing: a sequence of records  [kind:1][len_hi:1][len_lo:1][payload:len]. A record whose
 * len runs past the end of the input is truncated to what is left.
 *
 * Entropy: iodine draws login seeds and DNS ids from secure_random(), which calls libc's
 * arc4random_buf() (or getrandom()). The harness provides those two libc functions so a run
 * depends only on its input: every byte is 0, which makes the login challenge reproducible for
 * seeds (the password/seed hash a peer must answer is fixed). This mocks the OS entropy source,
 * not any iodine code.
 */
#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

void arc4random_buf(void *buf, size_t n)
{
	memset(buf, 0, n);
}

ssize_t getrandom(void *buf, size_t n, unsigned int flags)
{
	(void) flags;
	memset(buf, 0, n);
	return (ssize_t) n;
}

struct reader {
	const uint8_t *p;
	size_t left;
};

/* next record; returns 0 when the input is exhausted */
static int next_record(struct reader *r, int *kind, const uint8_t **data, size_t *len)
{
	size_t n;

	if (r->left < 3)
		return 0;
	*kind = r->p[0];
	n = ((size_t) r->p[1] << 8) | r->p[2];
	r->p += 3;
	r->left -= 3;
	if (n > r->left)
		n = r->left;
	*data = r->p;
	*len = n;
	r->p += n;
	r->left -= n;
	return 1;
}

#endif
