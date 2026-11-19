/*
 * In-process UDP sockets for the server and client harnesses.
 *
 * Mayhem's sandbox does not let a target create/bind network sockets (a real loopback socket
 * aborted every input), so the harnesses mock the libc socket calls iodine's udp.c, server.c and
 * client.c use: recvmsg/recvfrom/recv deliver one pending datagram queued with mock_deliver(),
 * sendmsg/sendto/send swallow what iodine sends and remember its first two bytes (the DNS id).
 * Only libc is replaced, no iodine code. A mock socket is a pipe fd (a real, unique descriptor
 * that select()/FD_SET/close accept); calls on any other fd go straight to the kernel.
 *
 * socket() returns a placeholder descriptor (a pipe end) for IPv4/IPv6 sockets, e.g. the one
 * tun_setip()/tun_setmtu() open only to issue interface ioctls (which the client harness mocks).
 *
 * recvmsg() also hands back the IP_PKTINFO control message (destination address) the kernel
 * would add for a socket with DSTADDR_SOCKOPT set, as open_udp() does.
 */
#ifndef FUZZ_NET_H
#define FUZZ_NET_H

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#define MOCK_MAX 4
#define MOCK_PKT (64 * 1024)

struct mock_sock {
	int fd;
	int wfd;
	struct sockaddr_in local;	/* this socket's address */
	struct sockaddr_in from;	/* source of the pending datagram */
	uint8_t buf[MOCK_PKT];
	size_t len;
	int pending;
	uint8_t last_sent[2];		/* first two bytes of the last datagram sent */
	size_t nsent;			/* datagrams sent */
};

static struct mock_sock mocks[MOCK_MAX];
static int n_mocks;

static struct mock_sock *mock_find(int fd)
{
	int i;

	for (i = 0; i < n_mocks; i++)
		if (mocks[i].fd == fd)
			return &mocks[i];
	return NULL;
}

/* a mock UDP socket bound to 127.0.0.1:port */
static struct mock_sock *mock_open(uint16_t port)
{
	struct mock_sock *m;
	int p[2];

	if (n_mocks >= MOCK_MAX || pipe(p) != 0)
		abort();
	m = &mocks[n_mocks++];
	memset(m, 0, sizeof(*m));
	m->fd = p[0];
	m->wfd = p[1];
	m->local.sin_family = AF_INET;
	m->local.sin_port = htons(port);
	m->local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	return m;
}

static void mock_addr(const struct mock_sock *m, struct sockaddr_storage *ss, socklen_t *len)
{
	memset(ss, 0, sizeof(*ss));
	memcpy(ss, &m->local, sizeof(m->local));
	*len = sizeof(m->local);
}

/* queue one datagram from `src` on `dst` (replaces an unread one) */
static void mock_deliver(struct mock_sock *dst, const struct mock_sock *src, const uint8_t *data, size_t len)
{
	if (len > MOCK_PKT)
		len = MOCK_PKT;
	memcpy(dst->buf, data, len);
	dst->len = len;
	dst->from = src->local;
	dst->pending = 1;
}

static void mock_reset(void)
{
	int i;

	for (i = 0; i < n_mocks; i++) {
		mocks[i].pending = 0;
		mocks[i].nsent = 0;
		memset(mocks[i].last_sent, 0, 2);
	}
}

int socket(int domain, int type, int protocol)
{
	int p[2];

	if (domain != AF_INET && domain != AF_INET6)
		return (int) syscall(SYS_socket, domain, type, protocol);
	if (pipe(p) != 0)
		return -1;
	close(p[1]);
	return p[0];
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
	struct mock_sock *m = mock_find(fd);
	size_t i, off = 0;

	if (!m)
		return syscall(SYS_recvmsg, fd, msg, flags);
	if (!m->pending) {
		errno = EAGAIN;
		return -1;
	}
	for (i = 0; i < msg->msg_iovlen && off < m->len; i++) {
		size_t n = m->len - off;
		if (n > msg->msg_iov[i].iov_len)
			n = msg->msg_iov[i].iov_len;
		memcpy(msg->msg_iov[i].iov_base, m->buf + off, n);
		off += n;
	}
	msg->msg_flags = off < m->len ? MSG_TRUNC : 0;
	if (msg->msg_name) {
		socklen_t n = msg->msg_namelen < sizeof(m->from) ? msg->msg_namelen : sizeof(m->from);
		memcpy(msg->msg_name, &m->from, n);
		msg->msg_namelen = sizeof(m->from);
	}
	if (msg->msg_control && msg->msg_controllen >= CMSG_SPACE(sizeof(struct in_pktinfo))) {
		struct cmsghdr *c = (struct cmsghdr *) msg->msg_control;
		struct in_pktinfo pi;

		memset(msg->msg_control, 0, msg->msg_controllen);
		memset(&pi, 0, sizeof(pi));
		pi.ipi_addr = m->local.sin_addr;
		pi.ipi_spec_dst = m->local.sin_addr;
		c->cmsg_level = IPPROTO_IP;
		c->cmsg_type = IP_PKTINFO;
		c->cmsg_len = CMSG_LEN(sizeof(pi));
		memcpy(CMSG_DATA(c), &pi, sizeof(pi));
		msg->msg_controllen = CMSG_SPACE(sizeof(pi));
	} else {
		msg->msg_controllen = 0;
	}
	if (!(flags & MSG_PEEK))
		m->pending = 0;
	return (ssize_t) off;
}

/* glibc declares the sockaddr arguments as transparent unions under _GNU_SOURCE */
ssize_t recvfrom(int fd, void *buf, size_t n, int flags, __SOCKADDR_ARG from, socklen_t *fromlen)
{
	struct msghdr msg;
	struct iovec iov;
	ssize_t r;

	if (!mock_find(fd))
		return syscall(SYS_recvfrom, fd, buf, n, flags, from.__sockaddr__, fromlen);
	iov.iov_base = buf;
	iov.iov_len = n;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = from.__sockaddr__;
	msg.msg_namelen = fromlen ? *fromlen : 0;
	if (!fromlen)
		msg.msg_name = NULL;
	r = recvmsg(fd, &msg, flags);
	if (r >= 0 && fromlen)
		*fromlen = msg.msg_namelen;
	return r;
}

ssize_t recv(int fd, void *buf, size_t n, int flags)
{
	struct sockaddr *none = NULL;
	return recvfrom(fd, buf, n, flags, none, NULL);
}

static ssize_t mock_sent(struct mock_sock *m, const struct iovec *iov, size_t iovlen)
{
	size_t i, total = 0, got = 0;

	for (i = 0; i < iovlen; i++) {
		const uint8_t *p = iov[i].iov_base;
		size_t j;
		for (j = 0; j < iov[i].iov_len && got < 2; j++)
			m->last_sent[got++] = p[j];
		total += iov[i].iov_len;
	}
	m->nsent++;
	return (ssize_t) total;
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
	struct mock_sock *m = mock_find(fd);

	if (!m)
		return syscall(SYS_sendmsg, fd, msg, flags);
	return mock_sent(m, msg->msg_iov, msg->msg_iovlen);
}

ssize_t sendto(int fd, const void *buf, size_t n, int flags, __CONST_SOCKADDR_ARG to, socklen_t tolen)
{
	struct mock_sock *m = mock_find(fd);
	struct iovec iov;

	if (!m)
		return syscall(SYS_sendto, fd, buf, n, flags, to.__sockaddr__, tolen);
	iov.iov_base = (void *) buf;
	iov.iov_len = n;
	return mock_sent(m, &iov, 1);
}

ssize_t send(int fd, const void *buf, size_t n, int flags)
{
	const struct sockaddr *none = NULL;
	return sendto(fd, buf, n, flags, none, 0);
}

#endif
