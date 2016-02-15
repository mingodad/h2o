/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Masahiro Nagano
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "picohttpparser.h"
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http1client.h"
#include "h2o/tunnel.h"

struct rp_generator_t {
    h2o_generator_t super;
    h2o_req_t *src_req;
    h2o_http1client_t *client;
    struct {
        h2o_iovec_t bufs[2]; /* first buf is the request line and headers, the second is the POST content */
        int is_head;
    } up_req;
    h2o_buffer_t *last_content_before_send;
    h2o_doublebuffer_t sending;
    int is_websocket_handshake;
};

struct rp_ws_upgrade_info_t {
    h2o_context_t *ctx;
    h2o_timeout_t *timeout;
    h2o_socket_t *upstream_sock;
};

static h2o_http1client_ctx_t *get_client_ctx(h2o_req_t *req)
{
    h2o_req_overrides_t *overrides = req->overrides;
    if (overrides != NULL && overrides->client_ctx != NULL)
        return overrides->client_ctx;
    return &req->conn->ctx->proxy.client_ctx;
}

static h2o_iovec_t rewrite_location(h2o_mem_pool_t *pool, const char *location, size_t location_len, h2o_url_t *match,
       const h2o_url_scheme_t *req_scheme, h2o_iovec_t req_authority, h2o_iovec_t req_basepath)
{
    h2o_url_t loc_parsed = {};
    h2o_iovec_t res = {};

    if (loc_parsed.parse(location, location_len) != 0)
        goto NoRewrite;
    if (loc_parsed.scheme != &H2O_URL_SCHEME_HTTP)
        goto NoRewrite;
    if (!h2o_io_vector_lcis(loc_parsed.host, match->host))
        goto NoRewrite;
    if (loc_parsed.get_port() != match->get_port())
        goto NoRewrite;
    if (loc_parsed.path.len < match->path.len)
        goto NoRewrite;
    if (memcmp(loc_parsed.path.base, match->path.base, match->path.len) != 0)
        goto NoRewrite;

    h2o_concat(res, pool, req_scheme->name, h2o_iovec_t::create(H2O_STRLIT("://")), req_authority, req_basepath,
         h2o_iovec_t::create(loc_parsed.path.base + match->path.len, loc_parsed.path.len - match->path.len));

NoRewrite:
    return res;
}

static h2o_iovec_t build_request_merge_headers(h2o_mem_pool_t *pool, h2o_iovec_t merged, h2o_iovec_t added, int seperator)
{
    if (added.len == 0)
        return merged;
    if (merged.len == 0)
        return added;

    size_t newlen = merged.len + 2 + added.len;
    char *buf = pool->alloc_for<char>(newlen);
    memcpy(buf, merged.base, merged.len);
    buf[merged.len] = seperator;
    buf[merged.len + 1] = ' ';
    memcpy(buf + merged.len + 2, added.base, added.len);
    merged.base = buf;
    merged.len = newlen;
    return merged;
}

static h2o_iovec_t build_request(h2o_req_t *req, int keepalive, int is_websocket_handshake)
{
    h2o_iovec_t buf;
    size_t offset = 0, remote_addr_len = SIZE_MAX;
    char remote_addr[NI_MAXHOST];
    struct sockaddr_storage ss;
    socklen_t sslen;
    h2o_iovec_t cookie_buf = {}, xff_buf = {}, via_buf = {};

    /* for x-f-f */
    if ((sslen = req->conn->callbacks->get_peername(req->conn, (sockaddr *)&ss)) != 0)
        remote_addr_len = h2o_socket_getnumerichost((sockaddr *)&ss, sslen, remote_addr);

    /* build response */
    buf.len = req->method.len + req->path.len + req->authority.len + 512;
    buf.base = req->pool.alloc_for<char>(buf.len);

#define RESERVE(sz) \
    { \
        size_t required = offset + sz + 4 /* for "\r\n\r\n" */; \
        if (required > buf.len) { \
            do { \
                buf.len *= 2; \
            } while (required > buf.len); \
            char *newp = req->pool.alloc_for<char>(buf.len); \
            memcpy(newp, buf.base, offset); \
            buf.base = newp; \
        } \
    }
#define APPEND(s, l) \
    { \
        memcpy(buf.base + offset, (s), (l)); \
        offset += (l); \
    }
#define APPEND_IOV(iov) APPEND((iov).base, (iov).len)
#define APPEND_CHAR(c) buf.base[offset++] = c
#define APPEND_STRLIT(lit) APPEND((lit), sizeof(lit) - 1)
#define FLATTEN_PREFIXED_VALUE(prefix, value, add_size) \
    { \
        RESERVE(sizeof(prefix) - 1 + value.len + 2 + add_size); \
        APPEND_STRLIT(prefix); \
        if (value.len != 0) { \
            APPEND(value.base, value.len); \
            if (add_size != 0) { \
                APPEND_CHAR(','); \
                APPEND_CHAR(' '); \
            } \
        } \
    }

    APPEND_IOV(req->method);
    APPEND_CHAR(' ');
    APPEND_IOV(req->path);
    APPEND_STRLIT(" HTTP/1.1\r\nconnection: ");
    if (is_websocket_handshake) {
        APPEND_STRLIT("upgrade\r\nupgrade: websocket\r\nhost: ");
    } else if (keepalive) {
        APPEND_STRLIT("keep-alive\r\nhost: ");
    } else {
        APPEND_STRLIT("close\r\nhost: ");
    }
    APPEND_IOV(req->authority);
    APPEND_CHAR('\r');
    APPEND_CHAR('\n');
    assert(offset <= buf.len);
    if (req->entity.base != NULL) {
        size_t extra_size = sizeof("content-length: 18446744073709551615");
        RESERVE(extra_size);
        offset += snprintf(buf.base + offset, extra_size, "content-length: %zu\r\n", req->entity.len);
    }
    {
        for (size_t idx = 0; idx != req->headers.size; ++idx) {
			auto h = req->headers[idx];
            if (h2o_iovec_is_token(h.name)) {
			   auto token = (h2o_token_t *)h.name;
			   if (token->proxy_should_drop) {
				   continue;
			   } else if (token == H2O_TOKEN_COOKIE) {
				   /* merge the cookie headers; see HTTP/2 8.1.2.5 and HTTP/1 (RFC6265 5.4) */
				   /* FIXME current algorithm is O(n^2) against the number of cookie headers */
				   cookie_buf = build_request_merge_headers(&req->pool, cookie_buf, h.value, ';');
				   continue;
			   } else if (token == H2O_TOKEN_VIA) {
				   via_buf = build_request_merge_headers(&req->pool, via_buf, h.value, ',');
				   continue;
			   } else if (token == H2O_TOKEN_X_FORWARDED_FOR) {
				   xff_buf = build_request_merge_headers(&req->pool, xff_buf, h.value, ',');
				   continue;
			   }
            }
            if (h2o_lcstris(h.name->base, h.name->len, H2O_STRLIT("x-forwarded-proto")))
   				continue;
            RESERVE(h.name->len + h.value.len + 4);
            APPEND_IOV(*h.name);
            APPEND_CHAR(':');
            APPEND_CHAR(' ');
            APPEND_IOV(h.value);
            APPEND_CHAR('\r');
            APPEND_CHAR('\n');
        }
    }
    if (cookie_buf.len != 0) {
        FLATTEN_PREFIXED_VALUE("cookie: ", cookie_buf, 0);
        APPEND_CHAR('\r');
        APPEND_CHAR('\n');
    }
    FLATTEN_PREFIXED_VALUE("x-forwarded-proto: ", req->input.scheme->name, 0);
    APPEND_CHAR('\r');
    APPEND_CHAR('\n');
    if (remote_addr_len != SIZE_MAX) {
        FLATTEN_PREFIXED_VALUE("x-forwarded-for: ", xff_buf, remote_addr_len);
        APPEND(remote_addr, remote_addr_len);
    } else {
        FLATTEN_PREFIXED_VALUE("x-forwarded-for: ", xff_buf, 0);
    }
    APPEND_CHAR('\r');
    APPEND_CHAR('\n');
    FLATTEN_PREFIXED_VALUE("via: ", via_buf, sizeof("1.1 ") - 1 + req->input.authority.len);
    if (req->version < 0x200) {
        APPEND_CHAR('1');
        APPEND_CHAR('.');
        APPEND_CHAR('0' + (0x100 <= req->version && req->version <= 0x109 ? req->version - 0x100 : 0));
    } else {
        APPEND_CHAR('2');
    }
    APPEND_CHAR(' ');
    APPEND_IOV(req->input.authority);
    APPEND_STRLIT("\r\n\r\n");

#undef RESERVE
#undef APPEND
#undef APPEND_IOV
#undef APPEND_STRLIT
#undef FLATTEN_PREFIXED_VALUE

    /* set the length */
    assert(offset <= buf.len);
    buf.len = offset;

    return buf;
}

static void do_close(h2o_generator_t *generator, h2o_req_t *req)
{
    auto self = (rp_generator_t *)generator;

    if (self->client != NULL) {
        self->client->cancel();
        self->client = NULL;
    }
}

static void do_send(struct rp_generator_t *self)
{
    h2o_iovec_t vecs[1];
    size_t veccnt;
    int is_eos;

    assert(self->sending.bytes_inflight == 0);

    vecs[0] = h2o_doublebuffer_prepare(&self->sending,
          self->client != NULL ? &self->client->sock->input : &self->last_content_before_send,
          self->src_req->preferred_chunk_size);

    if (self->client == NULL && vecs[0].len == self->sending.buf->size && self->last_content_before_send->size == 0) {
        veccnt = vecs[0].len != 0 ? 1 : 0;
        is_eos = 1;
    } else {
        if (vecs[0].len == 0)
            return;
        veccnt = 1;
        is_eos = 0;
    }
    self->src_req->send(vecs, veccnt, is_eos);
}

static void do_proceed(h2o_generator_t *generator, h2o_req_t *req)
{
    auto self = (rp_generator_t *)generator;

    h2o_doublebuffer_consume(&self->sending);
    do_send(self);
}

static void on_websocket_upgrade_complete(void *_info, h2o_socket_t *sock, size_t reqsize)
{
    auto info = (rp_ws_upgrade_info_t *)_info;

    if (sock != NULL) {
        h2o_tunnel_establish(info->ctx, sock, info->upstream_sock, info->timeout);
    } else {
        h2o_socket_t::close(info->upstream_sock);
    }
    h2o_mem_free(info);
}

static inline void on_websocket_upgrade(struct rp_generator_t *self, h2o_timeout_t *timeout)
{
    auto req = self->src_req;
    auto sock = self->client->steal_socket();
    auto info = h2o_mem_alloc_for<rp_ws_upgrade_info_t>();
    info->upstream_sock = sock;
    info->timeout = timeout;
    info->ctx = req->conn->ctx;
    h2o_http1_upgrade(req, NULL, 0, on_websocket_upgrade_complete, info);
}

static int on_body(h2o_http1client_t *client, const char *errstr)
{
    auto self = (rp_generator_t *)client->data;

    /* FIXME should there be a way to notify error downstream? */

    if (errstr != NULL) {
        /* detach the content */
        self->last_content_before_send = self->client->sock->input;
        h2o_buffer_init(&self->client->sock->input, &h2o_socket_buffer_prototype);
        self->client = NULL;
    }
    if (self->sending.bytes_inflight == 0)
        do_send(self);

    return 0;
}

static h2o_http1client_body_cb on_head(h2o_http1client_t *client, const char *errstr, int minor_version, int status,
          h2o_iovec_t msg, phr_header *headers, size_t num_headers)
{
    auto self = (rp_generator_t *)client->data;
    h2o_req_t *req = self->src_req;
    size_t i;

    if (errstr != NULL && errstr != h2o_http1client_error_is_eos) {
        self->client = NULL;
        req->log_error("lib/core/proxy.c", "%s", errstr);
        req->send_error(502, "Gateway Error", errstr, 0);
        return NULL;
    }

    /* copy the response (note: all the headers must be copied; http1client discards the input once we return from this callback) */
    req->res.status = status;
    req->res.reason = h2o_strdup(&req->pool, msg.base, msg.len).base;
    for (i = 0; i != num_headers; ++i) {
        auto token = h2o_lookup_token(headers[i].name, headers[i].name_len);
        h2o_iovec_t name, value;
        if (token != NULL) {
            if (token->proxy_should_drop) {
   				goto Skip;
            }
            if (token == H2O_TOKEN_CONTENT_LENGTH) {
			   if (req->res.content_length != SIZE_MAX ||
				   (req->res.content_length = h2o_pht_header_value_tosize(headers[i])) == SIZE_MAX) {
				   self->client = NULL;
				   req->log_error("lib/core/proxy.c", "%s", "invalid response from upstream (malformed content-length)");
				   req->send_error(502, "Gateway Error", "invalid response from upstream", 0);
				   return NULL;
			   }
			   goto Skip;
            } else if (token == H2O_TOKEN_LOCATION) {
			   if (req->res_is_delegated && (300 <= status && status <= 399) && status != 304) {
				   self->client = NULL;
				   h2o_iovec_t method = h2o_get_redirect_method(req->method, status);
				   req->send_redirect_internal(method, headers[i].value, headers[i].value_len, 1);
				   return NULL;
			   }
			   if (req->overrides != NULL && req->overrides->location_rewrite.match != NULL) {
				   value =
					   rewrite_location(&req->pool, headers[i].value, headers[i].value_len, req->overrides->location_rewrite.match,
						req->input.scheme, req->input.authority, req->overrides->location_rewrite.path_prefix);
				   if (value.base != NULL)
					   goto AddHeader;
			   }
			   goto AddHeaderDuped;
            } else if (token == H2O_TOKEN_LINK) {
   				req->puth_path_in_link_header(headers[i].value, headers[i].value_len);
            }
        /* default behaviour, transfer the header downstream */
        AddHeaderDuped:
            value.strdup(&req->pool, headers[i].value, headers[i].value_len);
        AddHeader:
            req->addResponseHeader(token, value);
        Skip:
            ;
        } else {
            name.strdup(&req->pool, headers[i].name, headers[i].name_len);
            value.strdup(&req->pool, headers[i].value, headers[i].value_len);
            req->res.headers.add(&req->pool, name.base, name.len, 0, value.base, value.len);
        }
    }

    if (self->is_websocket_handshake && req->res.status == 101) {
        auto client_ctx = get_client_ctx(req);
        assert(client_ctx->websocket_timeout != NULL);
        req->addResponseHeader(H2O_TOKEN_UPGRADE, H2O_STRLIT("websocket"));
        on_websocket_upgrade(self, client_ctx->websocket_timeout);
        self->client = NULL;
        return NULL;
    }
    /* declare the start of the response */
    req->start_response(&self->super);

    if (errstr == h2o_http1client_error_is_eos) {
        self->client = NULL;
        req->send(NULL, 0, 1);
        return NULL;
    }

    return on_body;
}

static h2o_http1client_head_cb on_connect(h2o_http1client_t *client, const char *errstr, h2o_iovec_t **reqbufs, size_t *reqbufcnt,
int *method_is_head)
{
    auto self = (rp_generator_t *)client->data;

    if (errstr != NULL) {
        self->client = NULL;
        self->src_req->log_error("lib/core/proxy.c", "%s", errstr);
        self->src_req->send_error(502, "Gateway Error", errstr, 0);
        return NULL;
    }

    *reqbufs = self->up_req.bufs;
    *reqbufcnt = self->up_req.bufs[1].base != NULL ? 2 : 1;
    *method_is_head = self->up_req.is_head;
    return on_head;
}

static void on_generator_dispose(void *_self)
{
    auto self = (rp_generator_t *)_self;

    if (self->client != NULL) {
        self->client->cancel();
        self->client = NULL;
    }
    h2o_buffer_dispose(&self->last_content_before_send);
    h2o_doublebuffer_dispose(&self->sending);
}

static struct rp_generator_t *proxy_send_prepare(h2o_req_t *req, int keepalive)
{
    auto self = req->pool.alloc_shared_for<rp_generator_t>(1, on_generator_dispose);
    h2o_http1client_ctx_t *client_ctx = get_client_ctx(req);

    self->super.proceed = do_proceed;
    self->super.stop = do_close;
    self->src_req = req;
    if (client_ctx->websocket_timeout != NULL && h2o_lcstris(req->upgrade.base, req->upgrade.len, H2O_STRLIT("websocket"))) {
        self->is_websocket_handshake = 1;
    } else {
        self->is_websocket_handshake = 0;
    }
    self->up_req.bufs[0] = build_request(req, keepalive, self->is_websocket_handshake);
    self->up_req.bufs[1] = req->entity;
    self->up_req.is_head = req->method.isEq("HEAD");
    h2o_buffer_init(&self->last_content_before_send, &h2o_socket_buffer_prototype);
    h2o_doublebuffer_init(&self->sending, &h2o_socket_buffer_prototype);

    return self;
}

void h2o__proxy_process_request(h2o_req_t *req)
{
    h2o_req_overrides_t *overrides = req->overrides;
    h2o_http1client_ctx_t *client_ctx = get_client_ctx(req);
    rp_generator_t *self;

    if (overrides != NULL) {
        if (overrides->socketpool != NULL) {
            self = proxy_send_prepare(req, 1);
            h2o_http1client_t::connect_with_pool(&self->client, self, client_ctx, overrides->socketpool, on_connect);
            return;
        } else if (overrides->hostport.host.base != NULL) {
            self = proxy_send_prepare(req, 0);
            h2o_http1client_t::connect(&self->client, self, client_ctx, req->overrides->hostport.host, req->overrides->hostport.port,
       on_connect);
            return;
        }
    }
    { /* default logic */
        h2o_iovec_t host;
        uint16_t port;
        if (req->scheme != &H2O_URL_SCHEME_HTTP ||
            h2o_url_parse_hostport(req->authority.base, req->authority.len, &host, &port) == NULL) {
            req->log_error("lib/core/proxy.c", "invalid URL supplied for internal redirection:%s://%.*s%.*s",
				 req->scheme->name.base, (int)req->authority.len, req->authority.base, (int)req->path.len,
				 req->path.base);
            req->send_error(502, "Gateway Error", "internal error", 0);
            return;
        }
        if (port == H2O_PORT_NOT_SET)
            port = 80;
        self = proxy_send_prepare(req, 0);
        h2o_http1client_t::connect(&self->client, self, client_ctx, host, port, on_connect);
        return;
    }
}
