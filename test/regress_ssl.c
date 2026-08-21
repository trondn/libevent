/*
 * Copyright (c) 2009-2012 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#include "util-internal.h"

#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include "event2/event.h"
#include "event2/bufferevent_ssl.h"
#include "event2/bufferevent_struct.h"
#include "event2/buffer.h"
#include "event2/listener.h"

#include "tinytest.h"
#include "tinytest_macros.h"

#include <string.h>
#ifdef _WIN32
#include <io.h>
#define read _read
#define write _write
#else
#include <unistd.h>
#endif

/* A pre-generated key, to save the cost of doing an RSA key generation step
 * during the unit tests. It is published in this file, so you would have to
 * be very foolish to consider using it in your own code. */
static const char KEY[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEogIBAAKCAQEAtK07Ili0dkJb79m/sFmHoVJTWyLoveXex2yX/BtUzzcvZEOu\n"
    "QLon/++5YOA48kzZm5K9mIwZkZhui1ZgJ5Bjq0LGAWTZGIn+NXjLFshPYvTKpOCW\n"
    "uzL0Ir0LXMsBLYJQ5A4FomLNxs4I3H/dhDSGy/rSiJB1B4w2xNiwPK08/VL3zZqk\n"
    "V+GsSvGIIkzhTMbqPJy9K8pqyjwOU2pgORS794yXciTGxWYjTDzJPgQ35YMDATaG\n"
    "jr4HHo1zxU/Lj0pndSUK5rKLYxYQ3Uc8B3AVYDl9CP/GbOoQ4LBzS68JjcAUyp6i\n"
    "6NfXlc2D9S9XgqVqwI+JqgJs0eW/+zPY2UEDWwIDAQABAoIBAD2HzV66FOM9YDAD\n"
    "2RtGskEHV2nvLpIVadRCsFPkPvK+2X3s6rgSbbLkwh4y3lHuSCGKTNVZyQ9jeSos\n"
    "xVxT+Q2HFQW+gYyw2gj91TQyDY8mzKhv8AVaqff2p5r3a7RC8CdqexK9UVUGL9Bg\n"
    "H2F5vfpTtkVZ5PEoGDLblNFlMiMW/t1SobUeBVx+Msco/xqk9lFv1A9nnepGy0Gi\n"
    "D+i6YNGTBsX22YhoCZl/ICxCL8lgqPei4FvBr9dBVh/jQgjuUBm2jz55p2r7+7Aw\n"
    "khmXHReejoVokQ2+htgSgZNKlKuDy710ZpBqnDi8ynQi82Y2qCpyg/p/xcER54B6\n"
    "hSftaiECgYEA2RkSoxU+nWk+BClQEUZRi88QK5W/M8oo1DvUs36hvPFkw3Jk/gz0\n"
    "fgd5bnA+MXj0Fc0QHvbddPjIkyoI/evq9GPV+JYIuH5zabrlI3Jvya8q9QpAcEDO\n"
    "KkL/O09qXVEW52S6l05nh4PLejyI7aTyTIN5nbVLac/+M8MY/qOjZksCgYEA1Q1o\n"
    "L8kjSavU2xhQmSgZb9W62Do60sa3e73ljrDPoiyvbExldpSdziFYxHBD/Rep0ePf\n"
    "eVSGS3VSwevt9/jSGo2Oa83TYYns9agBm03oR/Go/DukESdI792NsEM+PRFypVNy\n"
    "AohWRLj0UU6DV+zLKp0VBavtx0ATeLFX0eN17TECgYBI2O/3Bz7uhQ0JSm+SjFz6\n"
    "o+2SInp5P2G57aWu4VQWWY3tQ2p+EQzNaWam10UXRrXoxtmc+ktPX9e2AgnoYoyB\n"
    "myqGcpnUhqHlnZAb999o9r1cYidDQ4uqhLauSTSwwXAFDzjJYsa8o03Y440y6QFh\n"
    "CVD6yYXXqLJs3g96CqDexwKBgAHxq1+0QCQt8zVElYewO/svQhMzBNJjic0RQIT6\n"
    "zAo4yij80XgxhvcYiszQEW6/xobpw2JCCS+rFGQ8mOFIXfJsFD6blDAxp/3d2JXo\n"
    "MhRl+hrDGI4ng5zcsqxHEMxR2m/zwPiQ8eiSn3gWdVBaEsiCwmxY00ScKxFQ3PJH\n"
    "Vw4hAoGAdZLd8KfjjG6lg7hfpVqavstqVi9LOgkHeCfdjn7JP+76kYrgLk/XdkrP\n"
    "N/BHhtFVFjOi/mTQfQ5YfZImkm/1ePBy7437DT8BDkOxspa50kK4HPggHnU64h1w\n"
    "lhdEOj7mAgHwGwwVZWOgs9Lq6vfztnSuhqjha1daESY6kDscPIQ=\n"
    "-----END RSA PRIVATE KEY-----\n";

#ifndef SSL_SET_HOSTNAME
#define SSL_SET_HOSTNAME(ssl) ((void)0)
#endif

static int disable_tls_11_and_12 = 0;
static int disable_tls_13 = 0;
static int test_is_done;
static int n_connected;
static int got_close;
static int got_error;
static int got_timeout;
static int renegotiate_at = -1;
static int stop_when_connected;
static int pending_connect_events;
static struct event_base *exit_base;


/* ====================
   Here's a simple test: we read a number from the input, increment it, and
   reply, until we get to 1001.
*/

enum regress_openssl_type
{
	REGRESS_OPENSSL_SOCKETPAIR = 1,
	REGRESS_OPENSSL_FILTER = 2,
#ifdef SSL_renegotiate
	REGRESS_OPENSSL_RENEGOTIATE = 4,
#endif
	REGRESS_OPENSSL_OPEN = 8,
	REGRESS_OPENSSL_DIRTY_SHUTDOWN = 16,
	REGRESS_OPENSSL_FD = 32,

	REGRESS_OPENSSL_CLIENT = 64,
	REGRESS_OPENSSL_SERVER = 128,

	REGRESS_OPENSSL_FREED = 256,
	REGRESS_OPENSSL_TIMEOUT = 512,
	REGRESS_OPENSSL_SLEEP = 1024,

	REGRESS_OPENSSL_CLIENT_WRITE = 2048,

	REGRESS_DEFERRED_CALLBACKS = 4096,

	REGRESS_OPENSSL_BATCH_WRITE = 8192,
};

static void
bufferevent_ssl_check_fd(struct bufferevent *bev, int filter)
{
	tt_fd_op(bufferevent_getfd(bev), !=, EVUTIL_INVALID_SOCKET);
	tt_fd_op(bufferevent_setfd(bev, EVUTIL_INVALID_SOCKET), ==, 0);
	if (filter) {
		tt_fd_op(bufferevent_getfd(bev), !=, EVUTIL_INVALID_SOCKET);
	} else {
		tt_fd_op(bufferevent_getfd(bev), ==, EVUTIL_INVALID_SOCKET);
	}

end:
	;
}
static void
bufferevent_ssl_check_freed(struct bufferevent *bev)
{
	tt_int_op(event_pending(&bev->ev_read, EVLIST_ALL, NULL), ==, 0);
	tt_int_op(event_pending(&bev->ev_write, EVLIST_ALL, NULL), ==, 0);

end:
	;
}

static void
free_on_cb(struct bufferevent *bev, void *ctx)
{
	TT_BLATHER(("free_on_cb: %p", bev));
	bufferevent_free(bev);
}

static void
respond_to_number(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *b = bufferevent_get_input(bev);
	char *line;
	int n;
#ifdef SSL_renegotiate
	enum regress_openssl_type type;
	type = (enum regress_openssl_type)(size_t)ctx;
#endif

	line = evbuffer_readln(b, NULL, EVBUFFER_EOL_LF);
	if (! line)
		return;
	n = atoi(line);
	if (n <= 0)
		TT_FAIL(("Bad number: %s", line));
	free(line);
	TT_BLATHER(("The number was %d", n));
	if (n == 1001) {
		++test_is_done;
		bufferevent_free(bev); /* Should trigger close on other side. */
		return;
	}
#ifdef SSL_renegotiate
	if ((type & REGRESS_OPENSSL_CLIENT) && n == renegotiate_at) {
		SSL_renegotiate(bufferevent_ssl_get_ssl(bev));
	}
#endif
	++n;
	evbuffer_add_printf(bufferevent_get_output(bev),
	    "%d\n", n);
	TT_BLATHER(("Done reading; now writing."));
	bufferevent_enable(bev, EV_WRITE);
	// we shouldn't disable EV_READ here, otherwise we wouldn't got close cb
	// bufferevent_disable(bev, EV_READ);
}

static void
done_writing_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *b = bufferevent_get_output(bev);
	if (evbuffer_get_length(b))
		return;
	TT_BLATHER(("Done writing."));
	bufferevent_disable(bev, EV_WRITE);
	bufferevent_enable(bev, EV_READ);
}

static void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
	X509 *peer_cert = NULL;
	enum regress_openssl_type type;

	type = (enum regress_openssl_type)(size_t)ctx;

	TT_BLATHER(("Got event %d", (int)what));
	if (what & BEV_EVENT_CONNECTED) {
		SSL *ssl;
		++n_connected;
		ssl = bufferevent_ssl_get_ssl(bev);
		tt_assert(ssl);
#if OPENSSL_VERSION_NUMBER >= 0x30000000
		/* SSL_get1_peer_certificate() means we want
		 * to increase the reference count on the cert
		 * and so we will need to free it ourselves later
		 * when we're done with it. The non-reference count
		 * increasing version is not available in OpenSSL 1.1.1. */
		peer_cert = SSL_get1_peer_certificate(ssl);
#else
		peer_cert = SSL_get_peer_certificate(ssl);
#endif
		if (type & REGRESS_OPENSSL_SERVER) {
			tt_assert(peer_cert == NULL);
		} else {
			tt_assert(peer_cert != NULL);
		}
		if (stop_when_connected) {
			if (--pending_connect_events == 0)
				event_base_loopexit(exit_base, NULL);
		}

		if ((type & REGRESS_OPENSSL_CLIENT_WRITE) && (type & REGRESS_OPENSSL_CLIENT))
			evbuffer_add_printf(bufferevent_get_output(bev), "1\n");
	} else if (what & BEV_EVENT_EOF) {
		TT_BLATHER(("Got a good EOF"));
		++got_close;
		if (type & REGRESS_OPENSSL_FD) {
			bufferevent_ssl_check_fd(bev, type & REGRESS_OPENSSL_FILTER);
		}
		if (type & REGRESS_OPENSSL_FREED) {
			bufferevent_ssl_check_freed(bev);
		}
		bufferevent_free(bev);
	} else if (what & BEV_EVENT_ERROR) {
		TT_BLATHER(("Got an error."));
		++got_error;
		if (type & REGRESS_OPENSSL_FD) {
			bufferevent_ssl_check_fd(bev, type & REGRESS_OPENSSL_FILTER);
		}
		if (type & REGRESS_OPENSSL_FREED) {
			bufferevent_ssl_check_freed(bev);
		}
		bufferevent_free(bev);
	} else if (what & BEV_EVENT_TIMEOUT) {
		TT_BLATHER(("Got timeout."));
		++got_timeout;
		if (type & REGRESS_OPENSSL_FD) {
			bufferevent_ssl_check_fd(bev, type & REGRESS_OPENSSL_FILTER);
		}
		if (type & REGRESS_OPENSSL_FREED) {
			bufferevent_ssl_check_freed(bev);
		}
		bufferevent_free(bev);
	}

end:
	if (peer_cert)
		X509_free(peer_cert);
}

static void
open_ssl_bufevs(struct bufferevent **bev1_out, struct bufferevent **bev2_out,
    struct event_base *base, int is_open, int flags, SSL *ssl1, SSL *ssl2,
    evutil_socket_t *fd_pair, struct bufferevent **underlying_pair,
    enum regress_openssl_type type)
{
	int state1 = is_open ? BUFFEREVENT_SSL_OPEN :BUFFEREVENT_SSL_CONNECTING;
	int state2 = is_open ? BUFFEREVENT_SSL_OPEN :BUFFEREVENT_SSL_ACCEPTING;
	int dirty_shutdown = type & REGRESS_OPENSSL_DIRTY_SHUTDOWN;
	if (fd_pair) {
		*bev1_out = bufferevent_ssl_socket_new(
			base, fd_pair[0], ssl1, state1, flags);
		*bev2_out = bufferevent_ssl_socket_new(
			base, fd_pair[1], ssl2, state2, flags);
	} else {
		*bev1_out = bufferevent_ssl_filter_new(
			base, underlying_pair[0], ssl1, state1, flags);
		*bev2_out = bufferevent_ssl_filter_new(
			base, underlying_pair[1], ssl2, state2, flags);

	}
	bufferevent_setcb(*bev1_out, respond_to_number, done_writing_cb,
	    eventcb, (void*)(REGRESS_OPENSSL_CLIENT | (intptr_t)type));
	bufferevent_setcb(*bev2_out, respond_to_number, done_writing_cb,
	    eventcb, (void*)(REGRESS_OPENSSL_SERVER | (intptr_t)type));

	bufferevent_ssl_set_allow_dirty_shutdown(*bev1_out, dirty_shutdown);
	bufferevent_ssl_set_allow_dirty_shutdown(*bev2_out, dirty_shutdown);

	if (REGRESS_OPENSSL_BATCH_WRITE) {
		bufferevent_ssl_set_flags(*bev1_out, BUFFEREVENT_SSL_BATCH_WRITE);
		bufferevent_ssl_set_flags(*bev2_out, BUFFEREVENT_SSL_BATCH_WRITE);
	}
}

static void
regress_bufferevent_openssl(void *arg)
{
	struct basic_test_data *data = arg;

	struct bufferevent *bev1, *bev2;
	SSL *ssl1, *ssl2;
	int flags = BEV_OPT_DEFER_CALLBACKS;
	struct bufferevent *bev_ll[2] = { NULL, NULL };
	evutil_socket_t *fd_pair = NULL;

	enum regress_openssl_type type;
	type = (enum regress_openssl_type)(size_t)data->setup_data;

#ifdef SSL_renegotiate
	if (type & REGRESS_OPENSSL_RENEGOTIATE) {
		/*
		 * Disable TLS 1.3, so we negotiate something older to test
		 * renegotiation - renegotiation is not supported by the
		 * protocol any more.
		 */
		disable_tls_13 = 1;
		if (OPENSSL_VERSION_NUMBER >= 0x10001000 &&
		    OPENSSL_VERSION_NUMBER <  0x1000104f) {
			/* 1.0.1 up to 1.0.1c has a bug where TLS1.1 and 1.2
			 * can't renegotiate with themselves. Disable. */
			disable_tls_11_and_12 = 1;
		}
		renegotiate_at = 600;
	}
#endif

	ssl1 = SSL_new(get_ssl_ctx(SSL_IS_CLIENT));
	SSL_SET_HOSTNAME(ssl1);
	ssl2 = SSL_new(get_ssl_ctx(SSL_IS_SERVER));

	SSL_use_certificate(ssl2, the_cert);
	SSL_use_PrivateKey(ssl2, the_key);

	if (!(type & REGRESS_OPENSSL_OPEN))
		flags |= BEV_OPT_CLOSE_ON_FREE;

	if (!(type & REGRESS_OPENSSL_FILTER)) {
		tt_assert(type & REGRESS_OPENSSL_SOCKETPAIR);
		fd_pair = data->pair;
	} else {
		bev_ll[0] = bufferevent_socket_new(data->base, data->pair[0],
		    BEV_OPT_CLOSE_ON_FREE);
		bev_ll[1] = bufferevent_socket_new(data->base, data->pair[1],
		    BEV_OPT_CLOSE_ON_FREE);
	}

	open_ssl_bufevs(&bev1, &bev2, data->base, 0, flags, ssl1, ssl2,
	    fd_pair, bev_ll, type);

	if (!(type & REGRESS_OPENSSL_FILTER)) {
		tt_fd_op(bufferevent_getfd(bev1), ==, data->pair[0]);
	} else {
		tt_ptr_op(bufferevent_get_underlying(bev1), ==, bev_ll[0]);
	}

	if (type & REGRESS_OPENSSL_OPEN) {
		pending_connect_events = 2;
		stop_when_connected = 1;
		exit_base = data->base;
		event_base_dispatch(data->base);
		/* Okay, now the renegotiation is done.  Make new
		 * bufferevents to test opening in BUFFEREVENT_SSL_OPEN */
		flags |= BEV_OPT_CLOSE_ON_FREE;
		bufferevent_free(bev1);
		bufferevent_free(bev2);
		bev1 = bev2 = NULL;
		open_ssl_bufevs(&bev1, &bev2, data->base, 1, flags, ssl1, ssl2,
		    fd_pair, bev_ll, type);
	}

	if (!(type & REGRESS_OPENSSL_TIMEOUT)) {
		bufferevent_enable(bev1, EV_READ|EV_WRITE);
		bufferevent_enable(bev2, EV_READ|EV_WRITE);

		if (!(type & REGRESS_OPENSSL_CLIENT_WRITE))
			evbuffer_add_printf(bufferevent_get_output(bev1), "1\n");

		event_base_dispatch(data->base);

		tt_assert(test_is_done == 1);
		tt_assert(n_connected == 2);

		/* We don't handle shutdown properly yet */
		if (type & REGRESS_OPENSSL_DIRTY_SHUTDOWN) {
			tt_int_op(got_close, ==, 1);
			tt_int_op(got_error, ==, 0);
		} else {
			tt_int_op(got_error, ==, 1);
		}
		tt_int_op(got_timeout, ==, 0);
	} else {
		struct timeval t = { 2, 0 };

		bufferevent_enable(bev1, EV_READ|EV_WRITE);
		bufferevent_disable(bev2, EV_READ|EV_WRITE);

		bufferevent_set_timeouts(bev1, &t, &t);

		if (!(type & REGRESS_OPENSSL_CLIENT_WRITE))
			evbuffer_add_printf(bufferevent_get_output(bev1), "1\n");

		event_base_dispatch(data->base);

		tt_assert(test_is_done == 0);
		tt_assert(n_connected == 0);

		tt_int_op(got_close, ==, 0);
		tt_int_op(got_error, ==, 0);
		tt_int_op(got_timeout, ==, 1);

		bufferevent_free(bev2);
	}

end:
	return;
}

static void
acceptcb_deferred(evutil_socket_t fd, short events, void *arg)
{
	struct bufferevent *bev = arg;
	bufferevent_enable(bev, EV_READ|EV_WRITE);
}
static void
acceptcb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *addr, int socklen, void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev;
	enum regress_openssl_type type;
	SSL *ssl = SSL_new(get_ssl_ctx(SSL_IS_SERVER));

	type = (enum regress_openssl_type)(size_t)data->setup_data;

	SSL_use_certificate(ssl, the_cert);
	SSL_use_PrivateKey(ssl, the_key);

	bev = bufferevent_ssl_socket_new(
		data->base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING,
		BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	tt_assert(bev);

	bufferevent_setcb(bev, respond_to_number, NULL, eventcb,
	    (void*)(REGRESS_OPENSSL_SERVER));

	if (type & REGRESS_OPENSSL_SLEEP) {
		struct timeval when = { 1, 0 };
		event_base_once(data->base, -1, EV_TIMEOUT,
		    acceptcb_deferred, bev, &when);
		bufferevent_disable(bev, EV_READ|EV_WRITE);
	} else {
		bufferevent_enable(bev, EV_READ|EV_WRITE);
	}

	/* Only accept once, then disable ourself. */
	evconnlistener_disable(listener);

end:
	;
}

struct rwcount
{
	evutil_socket_t fd;
	size_t read;
	size_t write;
};

static void
regress_bufferevent_openssl_connect(void *arg)
{
	struct basic_test_data *data = arg;

	struct event_base *base = data->base;

	struct evconnlistener *listener;
	struct bufferevent *bev;
	struct sockaddr_in sin;
	struct sockaddr_storage ss;
	ev_socklen_t slen;
	SSL *ssl;
	struct rwcount rw = { -1, 0, 0 };
	enum regress_openssl_type type;

	type = (enum regress_openssl_type)(size_t)data->setup_data;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);

	memset(&ss, 0, sizeof(ss));
	slen = sizeof(ss);

	listener = evconnlistener_new_bind(base, acceptcb, data,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE,
	    -1, (struct sockaddr *)&sin, sizeof(sin));

	tt_assert(listener);
	tt_assert(evconnlistener_get_fd(listener) >= 0);

	ssl = SSL_new(get_ssl_ctx(SSL_IS_CLIENT));
	SSL_SET_HOSTNAME(ssl);
	tt_assert(ssl);

	bev = bufferevent_ssl_socket_new(
		data->base, -1, ssl,
		BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	tt_assert(bev);

	bufferevent_setcb(bev, respond_to_number, free_on_cb, eventcb,
	    (void*)(REGRESS_OPENSSL_CLIENT));

	tt_assert(getsockname(evconnlistener_get_fd(listener),
		(struct sockaddr*)&ss, &slen) == 0);
	tt_assert(slen == sizeof(struct sockaddr_in));
	tt_int_op(((struct sockaddr*)&ss)->sa_family, ==, AF_INET);

	tt_assert(0 ==
	    bufferevent_socket_connect(bev, (struct sockaddr*)&ss, slen));
	/* Possible only when we have fd, since be_openssl can and will overwrite
	 * bio otherwise before */
	if (type & REGRESS_OPENSSL_SLEEP) {
		rw.fd = bufferevent_getfd(bev);
		BIO_setup(ssl, &rw);
	}
	evbuffer_add_printf(bufferevent_get_output(bev), "1\n");
	bufferevent_enable(bev, EV_READ|EV_WRITE);

	event_base_dispatch(base);

	tt_int_op(rw.read, <=, 100);
	tt_int_op(rw.write, <=, 100);
end:
	evconnlistener_free(listener);
}

struct wm_context
{
	int server;
	int flags;
	struct evbuffer *data;
	size_t to_read;
	size_t wm_high;
	size_t limit;
	size_t get;
	struct bufferevent *bev;
	struct wm_context *neighbour;
};
static void
wm_transfer(struct bufferevent *bev, void *arg)
{
	struct wm_context *ctx = arg;
	struct evbuffer *in  = bufferevent_get_input(bev);
	struct evbuffer *out = bufferevent_get_output(bev);
	size_t len = evbuffer_get_length(in);
	size_t drain = len < ctx->to_read ? len : ctx->to_read;

	if (ctx->get >= ctx->limit) {
		TT_BLATHER(("wm_transfer-%s(%p): break",
			ctx->server ? "server" : "client", bev));
		bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
		bufferevent_disable(bev, EV_READ);
		if (ctx->neighbour->get >= ctx->neighbour->limit) {
			event_base_loopbreak(bufferevent_get_base(bev));
		}
	} else {
		ctx->get += drain;
		evbuffer_drain(in, drain);
	}

	TT_BLATHER(("wm_transfer-%s(%p): "
		"in: " EV_SIZE_FMT ", "
		"out: " EV_SIZE_FMT ", "
		"got: " EV_SIZE_FMT "",
		ctx->server ? "server" : "client", bev,
		evbuffer_get_length(in),
		evbuffer_get_length(out),
		ctx->get));

	evbuffer_add_buffer_reference(out, ctx->data);
}
static void
wm_eventcb(struct bufferevent *bev, short what, void *arg)
{
	struct wm_context *ctx = arg;
	TT_BLATHER(("wm_eventcb-%s(%p): %i",
		ctx->server ? "server" : "client", bev, what));
	if (what & BEV_EVENT_CONNECTED) {
	} else {
		ctx->get = 0;
	}
}
static void
wm_acceptcb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *addr, int socklen, void *arg)
{
	struct wm_context *ctx = arg;
	struct bufferevent *bev;
	struct event_base *base = evconnlistener_get_base(listener);
	SSL *ssl = SSL_new(get_ssl_ctx(SSL_IS_SERVER));

	SSL_use_certificate(ssl, the_cert);
	SSL_use_PrivateKey(ssl, the_key);

	bev = bufferevent_ssl_socket_new(
		base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING, ctx->flags);
	
	tt_assert(bev);

	TT_BLATHER(("wm_transfer-%s(%p): accept",
		ctx->server ? "server" : "client", bev));

	bufferevent_setwatermark(bev, EV_READ, 0, ctx->wm_high);
	bufferevent_setcb(bev, wm_transfer, NULL, wm_eventcb, ctx);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	ctx->bev = bev;

	/* Only accept once, then disable ourself. */
	evconnlistener_disable(listener);
end: 
	;
}
static void
regress_bufferevent_openssl_wm(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;

	struct evconnlistener *listener;
	struct bufferevent *bev;
	struct sockaddr_in sin;
	struct sockaddr_storage ss;
	enum regress_openssl_type type =
		(enum regress_openssl_type)(size_t)data->setup_data;
	int bev_flags = BEV_OPT_CLOSE_ON_FREE;
	ev_socklen_t slen;
	SSL *ssl;
	struct wm_context client, server;
	char *payload;
	size_t payload_len = 1<<10;
	size_t wm_high = 5<<10;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);

	memset(&ss, 0, sizeof(ss));
	slen = sizeof(ss);

	if (type & REGRESS_DEFERRED_CALLBACKS)
		bev_flags |= BEV_OPT_DEFER_CALLBACKS;

	memset(&client, 0, sizeof(client));
	memset(&server, 0, sizeof(server));
	client.server = 0;
	server.server = 1;
	client.flags = server.flags = bev_flags;
	client.data = evbuffer_new();
	server.data = evbuffer_new();
	payload = calloc(1, payload_len);
	memset(payload, 'A', payload_len);
	evbuffer_add(server.data, payload, payload_len);
	evbuffer_add(client.data, payload, payload_len);
	client.wm_high = server.wm_high = wm_high;
	client.limit = server.limit = wm_high<<3;
	client.to_read = server.to_read = payload_len>>1;

	TT_BLATHER(("openssl_wm: "
		"payload_len = " EV_SIZE_FMT ", "
		"wm_high = " EV_SIZE_FMT ", "
		"limit = " EV_SIZE_FMT ", "
		"to_read: " EV_SIZE_FMT "",
		payload_len,
		wm_high,
		server.limit,
		server.to_read));

	listener = evconnlistener_new_bind(base, wm_acceptcb, &server,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE,
	    -1, (struct sockaddr *)&sin, sizeof(sin));

	tt_assert(listener);
	tt_assert(evconnlistener_get_fd(listener) >= 0);

	ssl = SSL_new(get_ssl_ctx(SSL_IS_CLIENT));
	SSL_SET_HOSTNAME(ssl);
	tt_assert(ssl);

	if (type & REGRESS_OPENSSL_FILTER) {
		bev = bufferevent_socket_new(data->base, -1, client.flags);
		tt_assert(bev);
		bev = bufferevent_ssl_filter_new(
			base, bev, ssl, BUFFEREVENT_SSL_CONNECTING, client.flags);
	} else {
		bev = bufferevent_ssl_socket_new(
			data->base, -1, ssl,
			BUFFEREVENT_SSL_CONNECTING,
			client.flags);
	}
	tt_assert(bev);
	client.bev = bev;

	server.neighbour = &client;
	client.neighbour = &server;

	bufferevent_setwatermark(bev, EV_READ, 0, client.wm_high);
	bufferevent_setcb(bev, wm_transfer, NULL, wm_eventcb, &client);

	tt_assert(getsockname(evconnlistener_get_fd(listener),
		(struct sockaddr*)&ss, &slen) == 0);

	tt_assert(!bufferevent_socket_connect(bev, (struct sockaddr*)&ss, slen));
	tt_assert(!evbuffer_add_buffer_reference(bufferevent_get_output(bev), client.data));
	tt_assert(!bufferevent_enable(bev, EV_READ|EV_WRITE));

	event_base_dispatch(base);

	tt_int_op(client.get, ==, client.limit);
	tt_int_op(server.get, ==, server.limit);

end:
	free(payload);
	evbuffer_free(client.data);
	evbuffer_free(server.data);
	evconnlistener_free(listener);
	bufferevent_free(client.bev);
	bufferevent_free(server.bev);

	/* XXX: by some reason otherwise there is a leak */
	if (!(type & REGRESS_OPENSSL_FILTER))
		event_base_loop(base, EVLOOP_ONCE);
}

#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER > 0)
static void
bufferevent_openssl_recv_timestamps_readcb(struct bufferevent *bev, void *ctx)
{
	int *done = ctx;
	struct timespec ts;
	struct evbuffer *input;
	char tmp[32];
	int r;
	int ts_result;

	/* Fetch and verify timestamps BEFORE draining the buffer! */
	input = bufferevent_get_input(bev);
	ts_result = evbuffer_get_timestamp(input, &ts);

#if defined(__linux__) && defined(SO_TIMESTAMPNS)
	tt_int_op(ts_result, ==, 0);
	tt_assert(ts.tv_sec > 0);
#else
	tt_int_op(ts_result, ==, -1);
#endif

	r = bufferevent_read(bev, tmp, sizeof(tmp));
	tt_int_op(r, ==, 14);
	tt_mem_op(tmp, ==, "timestamp_test", 14);

	*done = 1;

 end:
	event_base_loopexit(bufferevent_get_base(bev), NULL);
}

static void
test_eventcb(struct bufferevent *bev, short what, void *ctx)
{
	TT_BLATHER(("test_eventcb: %p got event %d", bev, (int)what));
	if (what & BEV_EVENT_ERROR) {
		unsigned long err;
		while ((err = ERR_get_error())) {
			TT_BLATHER(("  SSL error: %s", ERR_error_string(err, NULL)));
		}
	}
}

static void
test_bufferevent_openssl_direct_recv_timestamps(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev1 = NULL;
	struct bufferevent *bev2 = NULL;
	SSL *ssl1 = NULL, *ssl2 = NULL;
	struct timespec ts;
	int done = 0;
	evutil_socket_t fd_pair[2] = { -1, -1 };

	/* Create a TCP socketpair */
	tt_assert(evutil_ersatz_socketpair_(AF_INET, SOCK_STREAM, 0, fd_pair) == 0);
	tt_assert(evutil_make_socket_nonblocking(fd_pair[0]) == 0);
	tt_assert(evutil_make_socket_nonblocking(fd_pair[1]) == 0);

	ssl1 = SSL_new(get_ssl_ctx());
	ssl2 = SSL_new(get_ssl_ctx());
	tt_assert(ssl1);
	tt_assert(ssl2);

	SSL_use_certificate(ssl2, the_cert);
	SSL_use_PrivateKey(ssl2, the_key);

	/* Create direct socket openssl bufferevents.
	 * bev2 has BEV_OPT_RECV_TIMESTAMPS enabled. */
	bev1 = bufferevent_openssl_socket_new(
		data->base, fd_pair[0], ssl1, BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	tt_assert(bev1);
	fd_pair[0] = -1;

	bev2 = bufferevent_openssl_socket_new(
		data->base, fd_pair[1], ssl2, BUFFEREVENT_SSL_ACCEPTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_RECV_TIMESTAMPS);
	tt_assert(bev2);
	fd_pair[1] = -1;

	/* Verify initially no timestamps are present */
	tt_int_op(evbuffer_get_timestamp(bufferevent_get_input(bev2), &ts), ==, -1);

	/* Configure callbacks */
	bufferevent_setcb(bev1, NULL, NULL, test_eventcb, NULL);
	bufferevent_setcb(bev2, bufferevent_openssl_recv_timestamps_readcb, NULL, test_eventcb, &done);
	tt_int_op(bufferevent_enable(bev1, EV_READ|EV_WRITE), ==, 0);
	tt_int_op(bufferevent_enable(bev2, EV_READ|EV_WRITE), ==, 0);

	{
		struct timeval tv_sleep = { 0, 10000 };
		evutil_usleep_(&tv_sleep);
	}

	/* Write data from bev1 */
	tt_int_op(bufferevent_write(bev1, "timestamp_test", 14), ==, 0);

	/* Dispatch base */
	event_base_dispatch(data->base);

	tt_int_op(done, ==, 1);

 end:
	if (bev1) {
		bufferevent_free(bev1);
	}
	if (bev2) {
		bufferevent_free(bev2);
	}
	if (fd_pair[0] >= 0) {
		evutil_closesocket(fd_pair[0]);
	}
	if (fd_pair[1] >= 0) {
		evutil_closesocket(fd_pair[1]);
	}
}

static void
bufferevent_openssl_filter_recv_timestamps_readcb(struct bufferevent *bev, void *ctx)
{
	int *done = ctx;
	struct timespec ts;
	struct evbuffer *input;
	char tmp[32];
	int r;
	int ts_result;

	input = bufferevent_get_input(bev);
	ts_result = evbuffer_get_timestamp(input, &ts);

#if defined(__linux__) && defined(SO_TIMESTAMPNS)
	tt_int_op(ts_result, ==, 0);
	tt_assert(ts.tv_sec > 0);
#else
	tt_int_op(ts_result, ==, -1);
#endif

	r = bufferevent_read(bev, tmp, sizeof(tmp));
	tt_int_op(r, ==, 9);
	tt_mem_op(tmp, ==, "test_data", 9);

	*done = 1;

 end:
	event_base_loopexit(bufferevent_get_base(bev), NULL);
}

static void
test_bufferevent_openssl_filter_recv_timestamps(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev1 = NULL;
	struct bufferevent *bev2 = NULL;
	struct bufferevent *underlying_bev1 = NULL;
	struct bufferevent *underlying_bev2 = NULL;
	SSL *ssl1 = NULL, *ssl2 = NULL;
	int done = 0;
	evutil_socket_t fd_pair[2] = {-1, -1};

	/* Create TCP socketpair */
	tt_assert(evutil_ersatz_socketpair_(AF_INET, SOCK_STREAM, 0, fd_pair) == 0);
	tt_assert(evutil_make_socket_nonblocking(fd_pair[0]) == 0);
	tt_assert(evutil_make_socket_nonblocking(fd_pair[1]) == 0);

	ssl1 = SSL_new(get_ssl_ctx());
	ssl2 = SSL_new(get_ssl_ctx());
	tt_assert(ssl1);
	tt_assert(ssl2);

	SSL_use_certificate(ssl2, the_cert);
	SSL_use_PrivateKey(ssl2, the_key);

	/* Create underlying socket bufferevents */
	underlying_bev1 = bufferevent_socket_new(data->base, fd_pair[0],
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	tt_assert(underlying_bev1);
	fd_pair[0] = -1;

	underlying_bev2 = bufferevent_socket_new(data->base, fd_pair[1],
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	tt_assert(underlying_bev2);
	fd_pair[1] = -1;

	/* Create filtered openssl bufferevents that wrap the socket bufferevents */
	bev1 = bufferevent_openssl_filter_new(data->base, underlying_bev1, ssl1,
		BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	tt_assert(bev1);
	underlying_bev1 = NULL; /* ownership transferred */

	bev2 = bufferevent_openssl_filter_new(data->base, underlying_bev2, ssl2,
		BUFFEREVENT_SSL_ACCEPTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_RECV_TIMESTAMPS);
	tt_assert(bev2);
	underlying_bev2 = NULL; /* ownership transferred */

	/* Configure callbacks for basic data flow */
	bufferevent_setcb(bev1, NULL, NULL, test_eventcb, NULL);
	bufferevent_setcb(bev2, bufferevent_openssl_filter_recv_timestamps_readcb, NULL, test_eventcb, &done);
	tt_int_op(bufferevent_enable(bev1, EV_READ | EV_WRITE), ==, 0);
	tt_int_op(bufferevent_enable(bev2, EV_READ | EV_WRITE), ==, 0);

	{
		struct timeval tv_sleep = { 0, 10000 };
		evutil_usleep_(&tv_sleep);
	}

	/* Write data from bev1 */
	tt_int_op(bufferevent_write(bev1, "test_data", 9), ==, 0);

	/* Dispatch base - just ensure filtered mode with timestamp code paths works
	 */
	event_base_dispatch(data->base);

	tt_int_op(done, ==, 1);

end:
	if (bev1) {
		bufferevent_free(bev1);
	}
	if (bev2) {
		bufferevent_free(bev2);
	}
	if (underlying_bev1) {
		bufferevent_free(underlying_bev1);
	}
	if (underlying_bev2) {
		bufferevent_free(underlying_bev2);
	}
	if (fd_pair[0] >= 0) {
		evutil_closesocket(fd_pair[0]);
	}
	if (fd_pair[1] >= 0) {
		evutil_closesocket(fd_pair[1]);
	}
}

static void
test_bufferevent_openssl_split_bio_recv_timestamps(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev = NULL;
	SSL *ssl = NULL;
	BIO *rbio = NULL, *wbio = NULL;
	evutil_socket_t fd_r = -1, fd_w = -1;

	/* Two distinct TCP sockets, so SO_TIMESTAMP can be armed on the
	 * write-side fd while rbio/wbio remain genuinely distinct BIOs, as
	 * happens with SSL_set_rfd()/SSL_set_wfd() or a read-side filter
	 * chain installed via SSL_set_bio(). */
	fd_r = socket(AF_INET, SOCK_STREAM, 0);
	tt_assert(fd_r != EVUTIL_INVALID_SOCKET);
	tt_assert(evutil_make_socket_nonblocking(fd_r) == 0);
	fd_w = socket(AF_INET, SOCK_STREAM, 0);
	tt_assert(fd_w != EVUTIL_INVALID_SOCKET);
	tt_assert(evutil_make_socket_nonblocking(fd_w) == 0);

	ssl = SSL_new(get_ssl_ctx());
	tt_assert(ssl);

	rbio = BIO_new_socket((int)fd_r, BIO_NOCLOSE);
	tt_assert(rbio);
	wbio = BIO_new_socket((int)fd_w, BIO_NOCLOSE);
	tt_assert(wbio);
	SSL_set_bio(ssl, rbio, wbio); /* ssl now owns rbio/wbio */

	/* BUFFEREVENT_SSL_OPEN skips the handshake, so this only exercises
	 * bufferevent_openssl_socket_new()'s BIO setup logic. */
	bev = bufferevent_openssl_socket_new(data->base, -1, ssl,
	    BUFFEREVENT_SSL_OPEN,
	    BEV_OPT_CLOSE_ON_FREE | BEV_OPT_RECV_TIMESTAMPS);
	tt_assert(bev);

	/* The rbio/wbio must be left untouched: SSL_set_bio() replaces both
	 * slots at once, so blindly calling it here for a split pair would
	 * silently free the real rbio (losing any buffered read state) and
	 * redirect reads onto the write-side fd. */
	tt_ptr_op(SSL_get_rbio(ssl), ==, rbio);
	tt_ptr_op(SSL_get_wbio(ssl), ==, wbio);

	/* fd_w must not have had SO_TIMESTAMP(NS) armed on it either: it's
	 * the write-side fd, not the one data is actually read from, so
	 * arming it would just be a wasted/misleading setsockopt() on the
	 * wrong socket. */
	{
		int on = 0;
		ev_socklen_t len = sizeof(on);
#ifdef SO_TIMESTAMPNS
		tt_assert(getsockopt(fd_w, SOL_SOCKET, SO_TIMESTAMPNS, &on, &len) == 0);
		tt_int_op(on, ==, 0);
#elif defined(SO_TIMESTAMP)
		tt_assert(getsockopt(fd_w, SOL_SOCKET, SO_TIMESTAMP, &on, &len) == 0);
		tt_int_op(on, ==, 0);
#endif
	}

 end:
	if (bev) {
		/* Frees ssl (BEV_OPT_CLOSE_ON_FREE), which frees rbio/wbio and
		 * closes fd_w; fd_r is not owned by anything here. */
		bufferevent_free(bev);
	} else {
		/* No bev means fd_w's ownership was never handed off: wbio
		 * (if any) was created BIO_NOCLOSE, so freeing ssl does not
		 * close it, and fd_w must be closed here instead. */
		if (ssl) {
			SSL_free(ssl);
		}
		if (fd_w != -1) {
			evutil_closesocket(fd_w);
		}
	}
	if (fd_r != -1) {
		evutil_closesocket(fd_r);
	}
}

static void
bufferevent_openssl_recv_ts_interleaved_readcb(struct bufferevent *bev, void *ctx)
{
	struct timespec *out_ts = ctx;
	char tmp[32];
	int r;

	/* Fetch the timestamp BEFORE draining the buffer! */
	tt_int_op(evbuffer_get_timestamp(bufferevent_get_input(bev), out_ts), ==, 0);

	r = bufferevent_read(bev, tmp, sizeof(tmp));
	tt_int_op(r, ==, 9);
	tt_mem_op(tmp, ==, "chunkedts", 9);

 end:
	event_base_loopexit(bufferevent_get_base(bev), NULL);
}

static void
bufferevent_openssl_recv_ts_interleaved_eventcb(struct bufferevent *bev, short what, void *ctx)
{
	int *connected = ctx;
	if (what & BEV_EVENT_CONNECTED) {
		*connected = 1;
	}
	if (what & BEV_EVENT_ERROR) {
		unsigned long err;
		while ((err = ERR_get_error())) {
			TT_BLATHER(("  SSL error: %s", ERR_error_string(err, NULL)));
		}
	}
}

/* Regression test for the bug fixed alongside this test: do_write() and
 * do_handshake() used to unconditionally clear any BIO-cached recv
 * timestamp, including one a still-in-progress do_read() was waiting to
 * consume. So a write interleaved between the two recvmsg() calls needed
 * to reassemble a single TLS record (because it arrived as two separate
 * physical reads) would cause the record to be attributed the *second*
 * recvmsg()'s timestamp instead of the first (oldest) one.
 *
 * To reproduce that deterministically:
 *  1. Encrypt one small record via a direct SSL_write() into a memory
 *     BIO, so we get our hands on the exact ciphertext bytes without
 *     letting OpenSSL send them.
 *  2. send() the first half of those bytes raw, and let the receiving
 *     bufferevent_openssl partially read it: not enough ciphertext yet,
 *     so SSL_read() returns WANT_READ and the timestamp of this first
 *     read is cached, unconsumed.
 *  3. Capture a wall-clock cutoff, then perform an ordinary write on the
 *     *receiving* bufferevent, forcing its do_write() to run while that
 *     cached timestamp is still pending.
 *  4. send() the second half of the ciphertext -- necessarily stamped
 *     with a kernel timestamp *after* the cutoff -- and let do_read()
 *     finish reassembling the record.
 * With the bug, the record ends up stamped with the second (post-cutoff)
 * recvmsg()'s timestamp; with the fix, it keeps the first (pre-cutoff)
 * one. A plain "is there a timestamp at all" check can't tell the two
 * apart, since both would report success either way.
 *
 * Some platforms' kernels never deliver TCP receive timestamps at all
 * (e.g. macOS treats SO_TIMESTAMP on SOCK_STREAM sockets as a silent
 * no-op); a single ordinary write is used as an upfront probe for that,
 * and the test skips instead of asserting anything meaningless if it
 * doesn't work. */
static void
test_bufferevent_openssl_recv_ts_interleaved_write(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev1 = NULL;
	struct bufferevent *bev2 = NULL;
	SSL *ssl1 = NULL, *ssl2 = NULL;
	BIO *mem_wbio = NULL;
	struct timespec ts;
	struct timeval cutoff;
	char tmp[32];
	int connected = 0;
	int i;
	unsigned char *ciphertext = NULL;
	long ciphertext_len;
	long first_len;
	evutil_socket_t fd_send;
	evutil_socket_t fd_pair[2] = { -1, -1 };
	int r;

	tt_assert(evutil_ersatz_socketpair_(AF_INET, SOCK_STREAM, 0, fd_pair) == 0);
	tt_assert(evutil_make_socket_nonblocking(fd_pair[0]) == 0);
	tt_assert(evutil_make_socket_nonblocking(fd_pair[1]) == 0);

	ssl1 = SSL_new(get_ssl_ctx());
	ssl2 = SSL_new(get_ssl_ctx());
	tt_assert(ssl1);
	tt_assert(ssl2);

	SSL_use_certificate(ssl2, the_cert);
	SSL_use_PrivateKey(ssl2, the_key);

	/* bev1 is the sender: a plain OpenSSL client, no timestamps needed.
	 * bev2 is the receiver under test. */
	bev1 = bufferevent_openssl_socket_new(
		data->base, fd_pair[0], ssl1, BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE);
	tt_assert(bev1);
	fd_pair[0] = -1;

	bev2 = bufferevent_openssl_socket_new(
		data->base, fd_pair[1], ssl2, BUFFEREVENT_SSL_ACCEPTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_RECV_TIMESTAMPS);
	tt_assert(bev2);
	fd_pair[1] = -1;

	bufferevent_setcb(bev1, NULL, NULL,
	    bufferevent_openssl_recv_ts_interleaved_eventcb, &connected);
	bufferevent_setcb(bev2, NULL, NULL, test_eventcb, NULL);
	tt_int_op(bufferevent_enable(bev1, EV_READ|EV_WRITE), ==, 0);
	tt_int_op(bufferevent_enable(bev2, EV_READ|EV_WRITE), ==, 0);

	/* Drive the handshake to completion. */
	for (i = 0; i < 100 && !connected; ++i) {
		event_base_loop(data->base, EVLOOP_ONCE);
	}
	tt_assert(connected);

	/* Probe: does this platform's kernel deliver TCP recv timestamps at
	 * all? An ordinary single-shot write should get one if so. */
	tt_int_op(bufferevent_write(bev1, "probe", 5), ==, 0);
	for (i = 0; i < 100 && evbuffer_get_length(bufferevent_get_input(bev2)) < 5; ++i) {
		event_base_loop(data->base, EVLOOP_ONCE);
	}
	tt_int_op(evbuffer_get_length(bufferevent_get_input(bev2)), ==, 5);
	if (evbuffer_get_timestamp(bufferevent_get_input(bev2), &ts) != 0) {
		tt_skip();
	}
	tt_int_op(bufferevent_read(bev2, tmp, sizeof(tmp)), ==, 5);

	/* Encrypt the real test record into a memory BIO instead of letting
	 * it go out over the wire, so we can send its ciphertext ourselves
	 * in two separate raw chunks. */
	mem_wbio = BIO_new(BIO_s_mem());
	tt_assert(mem_wbio);
	SSL_set_bio(ssl1, SSL_get_rbio(ssl1), mem_wbio); /* ssl1 now owns mem_wbio */

	r = SSL_write(ssl1, "chunkedts", 9);
	tt_int_op(r, ==, 9);

	ciphertext_len = BIO_get_mem_data(mem_wbio, &ciphertext);
	tt_assert(ciphertext_len > 1);
	first_len = ciphertext_len / 2;

	fd_send = bufferevent_getfd(bev1);
	tt_assert(fd_send >= 0);

	/* Send the first half; let bev2 partially read it (not enough
	 * ciphertext for a full record yet, so SSL_read() returns
	 * WANT_READ and the timestamp of this read is cached, pending). */
	r = send(fd_send, (char *)ciphertext, first_len, 0);
	tt_int_op(r, ==, first_len);
	event_base_loop(data->base, EVLOOP_ONCE);

	/* Everything sent after this point is necessarily stamped later by
	 * the kernel than everything already delivered above. */
	tt_assert(evutil_gettimeofday(&cutoff, NULL) == 0);

	/* Interleave an ordinary write on bev2 -- the receiver -- forcing
	 * its do_write() to run while the timestamp above is still
	 * pending. */
	tt_int_op(bufferevent_write(bev2, "X", 1), ==, 0);
	event_base_loop(data->base, EVLOOP_ONCE);

	/* Send the second half; bev2 can now finish reassembling the
	 * record. */
	r = send(fd_send, (char *)ciphertext + first_len, ciphertext_len - first_len, 0);
	tt_int_op(r, ==, ciphertext_len - first_len);

	bufferevent_setcb(bev2, bufferevent_openssl_recv_ts_interleaved_readcb,
	    NULL, test_eventcb, &ts);
	event_base_dispatch(data->base);

	/* The record must be stamped with the first (pre-cutoff) recvmsg()'s
	 * timestamp, not the second (post-cutoff) one. */
	tt_assert(ts.tv_sec < cutoff.tv_sec ||
	    (ts.tv_sec == cutoff.tv_sec && ts.tv_nsec < cutoff.tv_usec * 1000L));

 end:
	if (bev1) {
		bufferevent_free(bev1);
	}
	if (bev2) {
		bufferevent_free(bev2);
	}
	if (fd_pair[0] >= 0) {
		evutil_closesocket(fd_pair[0]);
	}
	if (fd_pair[1] >= 0) {
		evutil_closesocket(fd_pair[1]);
	}
}

/* Regression test: has_recv_ts must be retired once SSL_pending() has no
 * more leftover decrypted bytes from the read it was captured for.
 * Without that, bio_socket_recvmsg_read() would refuse to ever record a
 * new timestamp again once has_recv_ts got set once, so every record
 * after the first would be silently mis-attributed to the very first
 * timestamp ever captured on the connection -- two records sent well
 * apart in time would still come back with identical timestamps. */
static void
test_bufferevent_openssl_recv_ts_multiple_records(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev1 = NULL;
	struct bufferevent *bev2 = NULL;
	SSL *ssl1 = NULL, *ssl2 = NULL;
	struct timespec ts1, ts2;
	struct timeval delay = { 0, 20 * 1000 };
	char tmp[32];
	int connected = 0;
	int i;
	evutil_socket_t fd_pair[2] = { -1, -1 };

	tt_assert(evutil_ersatz_socketpair_(AF_INET, SOCK_STREAM, 0, fd_pair) == 0);
	tt_assert(evutil_make_socket_nonblocking(fd_pair[0]) == 0);
	tt_assert(evutil_make_socket_nonblocking(fd_pair[1]) == 0);

	ssl1 = SSL_new(get_ssl_ctx());
	ssl2 = SSL_new(get_ssl_ctx());
	tt_assert(ssl1);
	tt_assert(ssl2);

	SSL_use_certificate(ssl2, the_cert);
	SSL_use_PrivateKey(ssl2, the_key);

	bev1 = bufferevent_openssl_socket_new(
		data->base, fd_pair[0], ssl1, BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE);
	tt_assert(bev1);
	fd_pair[0] = -1;

	bev2 = bufferevent_openssl_socket_new(
		data->base, fd_pair[1], ssl2, BUFFEREVENT_SSL_ACCEPTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_RECV_TIMESTAMPS);
	tt_assert(bev2);
	fd_pair[1] = -1;

	bufferevent_setcb(bev1, NULL, NULL,
	    bufferevent_openssl_recv_ts_interleaved_eventcb, &connected);
	bufferevent_setcb(bev2, NULL, NULL, test_eventcb, NULL);
	tt_int_op(bufferevent_enable(bev1, EV_READ|EV_WRITE), ==, 0);
	tt_int_op(bufferevent_enable(bev2, EV_READ|EV_WRITE), ==, 0);

	/* Drive the handshake to completion. */
	for (i = 0; i < 100 && !connected; ++i) {
		event_base_loop(data->base, EVLOOP_ONCE);
	}
	tt_assert(connected);

	/* First record. */
	tt_int_op(bufferevent_write(bev1, "record-one", 10), ==, 0);
	for (i = 0; i < 100 && evbuffer_get_length(bufferevent_get_input(bev2)) < 10; ++i) {
		event_base_loop(data->base, EVLOOP_ONCE);
	}
	tt_int_op(evbuffer_get_length(bufferevent_get_input(bev2)), ==, 10);
	if (evbuffer_get_timestamp(bufferevent_get_input(bev2), &ts1) != 0) {
		/* This platform/sandbox doesn't actually deliver kernel recv
		 * timestamps at runtime; nothing to regress-test here. */
		tt_skip();
	}
	tt_int_op(bufferevent_read(bev2, tmp, sizeof(tmp)), ==, 10);

	/* Make sure the kernel clock actually advances before the next
	 * record is sent, so a stuck timestamp can't accidentally read back
	 * as correct. */
	evutil_usleep_(&delay);

	/* Second, entirely separate record. */
	tt_int_op(bufferevent_write(bev1, "record-two", 10), ==, 0);
	for (i = 0; i < 100 && evbuffer_get_length(bufferevent_get_input(bev2)) < 10; ++i) {
		event_base_loop(data->base, EVLOOP_ONCE);
	}
	tt_int_op(evbuffer_get_length(bufferevent_get_input(bev2)), ==, 10);
	tt_int_op(evbuffer_get_timestamp(bufferevent_get_input(bev2), &ts2), ==, 0);
	tt_int_op(bufferevent_read(bev2, tmp, sizeof(tmp)), ==, 10);

	tt_assert(ts2.tv_sec > ts1.tv_sec ||
	    (ts2.tv_sec == ts1.tv_sec && ts2.tv_nsec > ts1.tv_nsec));

 end:
	if (bev1) {
		bufferevent_free(bev1);
	}
	if (bev2) {
		bufferevent_free(bev2);
	}
	if (fd_pair[0] >= 0) {
		evutil_closesocket(fd_pair[0]);
	}
	if (fd_pair[1] >= 0) {
		evutil_closesocket(fd_pair[1]);
	}
}
#endif

struct testcase_t TESTCASES_NAME[] = {
#define T(a) ((void *)(a))
	{ "bufferevent_socketpair", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup, T(REGRESS_OPENSSL_SOCKETPAIR) },
	{ "bufferevent_socketpair_batch_write", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup, T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_BATCH_WRITE) },
	{ "bufferevent_socketpair_write_after_connect", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR|REGRESS_OPENSSL_CLIENT_WRITE) },
	{ "bufferevent_filter", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup, T(REGRESS_OPENSSL_FILTER) },
	{ "bufferevent_filter_write_after_connect", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_FILTER|REGRESS_OPENSSL_CLIENT_WRITE) },
#ifdef SSL_renegotiate
	{ "bufferevent_renegotiate_socketpair", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_RENEGOTIATE) },
	{ "bufferevent_renegotiate_filter", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_RENEGOTIATE) },
#endif
	{ "bufferevent_socketpair_startopen", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_OPEN) },
	{ "bufferevent_filter_startopen", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_OPEN) },

	{ "bufferevent_socketpair_dirty_shutdown", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },
	{ "bufferevent_filter_dirty_shutdown", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },
#ifdef SSL_renegotiate
	{ "bufferevent_renegotiate_socketpair_dirty_shutdown",
	  regress_bufferevent_openssl,
	  TT_ISOLATED,
	  &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_RENEGOTIATE | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },
	{ "bufferevent_renegotiate_filter_dirty_shutdown",
	  regress_bufferevent_openssl,
	  TT_ISOLATED,
	  &ssl_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_RENEGOTIATE | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },
#endif
	{ "bufferevent_socketpair_startopen_dirty_shutdown",
	  regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_OPEN | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },
	{ "bufferevent_filter_startopen_dirty_shutdown",
	  regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_OPEN | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },

	{ "bufferevent_socketpair_fd", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_FD) },
	{ "bufferevent_socketpair_freed", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_FREED) },
	{ "bufferevent_socketpair_freed_fd", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_FREED | REGRESS_OPENSSL_FD) },
	{ "bufferevent_filter_freed_fd", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_FREED | REGRESS_OPENSSL_FD) },

	{ "bufferevent_socketpair_timeout", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_TIMEOUT) },
	{ "bufferevent_socketpair_timeout_freed_fd", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_TIMEOUT | REGRESS_OPENSSL_FREED | REGRESS_OPENSSL_FD) },
	{ "bufferevent_connect", regress_bufferevent_openssl_connect,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, NULL },
	{ "bufferevent_connect_sleep", regress_bufferevent_openssl_connect,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, T(REGRESS_OPENSSL_SLEEP) },
	{ "bufferevent_wm", regress_bufferevent_openssl_wm,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, NULL },
	{ "bufferevent_wm_filter", regress_bufferevent_openssl_wm,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, T(REGRESS_OPENSSL_FILTER) },
	{ "bufferevent_wm_defer", regress_bufferevent_openssl_wm,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, T(REGRESS_DEFERRED_CALLBACKS) },
	{ "bufferevent_wm_filter_defer", regress_bufferevent_openssl_wm,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, T(REGRESS_OPENSSL_FILTER|REGRESS_DEFERRED_CALLBACKS) },
#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER > 0)
	{ "bufferevent_openssl_direct_recv_timestamps", test_bufferevent_openssl_direct_recv_timestamps,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, NULL },
	{ "bufferevent_openssl_filter_recv_timestamps", test_bufferevent_openssl_filter_recv_timestamps,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, NULL },
	{ "bufferevent_openssl_split_bio_recv_timestamps", test_bufferevent_openssl_split_bio_recv_timestamps,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, NULL },
	{ "bufferevent_openssl_recv_ts_interleaved_write", test_bufferevent_openssl_recv_ts_interleaved_write,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, NULL },
	{ "bufferevent_openssl_recv_ts_multiple_records", test_bufferevent_openssl_recv_ts_multiple_records,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, NULL },
#endif

#undef T

	END_OF_TESTCASES,
};
