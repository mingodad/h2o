/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku
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
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"

struct h2o_accept_data_t {
    h2o_accept_ctx_t *ctx;
    h2o_socket_t *sock;
    h2o_timeout_entry_t timeout;
    h2o_memcached_req_t *async_resumption_get_req;
    struct timeval connected_at;
};

static void on_accept_timeout(h2o_timeout_entry_t *entry);

static h2o_accept_data_t *create_accept_data(h2o_accept_ctx_t *ctx, h2o_socket_t *sock, struct timeval connected_at)
{
    auto data = h2o_mem_alloc_for<h2o_accept_data_t>();

    data->ctx = ctx;
    data->sock = sock;
    data->timeout = {};
    data->timeout.cb = on_accept_timeout;
    data->timeout.data = data;
    ctx->ctx->handshake_timeout.start(ctx->ctx->loop, &data->timeout);
    data->async_resumption_get_req = NULL;
    data->connected_at = connected_at;

    sock->data = data;
    return data;
}

static void free_accept_data(struct h2o_accept_data_t *data)
{
    assert(data->async_resumption_get_req == NULL);
    data->timeout.stop();
    h2o_mem_free(data);
}

static struct {
    h2o_memcached_context_t *memc;
    unsigned expiration;
} async_resumption_context;

static void async_resumption_on_get(h2o_iovec_t session_data, void *_accept_data)
{
    auto accept_data = (h2o_accept_data_t *)_accept_data;
    accept_data->async_resumption_get_req = NULL;
    accept_data->sock->ssl_resume_server_handshake(session_data);
}

static void async_resumption_get(h2o_socket_t *sock, h2o_iovec_t session_id)
{
    auto data = (h2o_accept_data_t *)sock->data;

    data->async_resumption_get_req =
        async_resumption_context.memc->get(data->ctx->libmemcached_receiver, session_id, async_resumption_on_get,
                          data, H2O_MEMCACHED_ENCODE_KEY | H2O_MEMCACHED_ENCODE_VALUE);
}

static void async_resumption_new(h2o_iovec_t session_id, h2o_iovec_t session_data)
{
    async_resumption_context.memc->set(session_id, session_data,
                      (uint32_t)time(NULL) + async_resumption_context.expiration,
                      H2O_MEMCACHED_ENCODE_KEY | H2O_MEMCACHED_ENCODE_VALUE);
}

static void async_resumption_remove(h2o_iovec_t session_id)
{
    async_resumption_context.memc->remove(session_id, H2O_MEMCACHED_ENCODE_KEY);
}

void h2o_accept_setup_async_ssl_resumption(h2o_memcached_context_t *memc, unsigned expiration)
{
    async_resumption_context.memc = memc;
    async_resumption_context.expiration = expiration;
    h2o_socket_ssl_async_resumption_init(async_resumption_get, async_resumption_new, async_resumption_remove);
}

void on_accept_timeout(h2o_timeout_entry_t *entry)
{
    /* TODO log */
    auto data = (h2o_accept_data_t*)entry->data;
    if (data->async_resumption_get_req != NULL) {
        async_resumption_context.memc->cancel_get(data->async_resumption_get_req);
        data->async_resumption_get_req = NULL;
    }
    h2o_socket_t *sock = data->sock;
    free_accept_data(data);
    h2o_socket_t::close(sock);
}

static void on_ssl_handshake_complete(h2o_socket_t *sock, int status)
{
    auto data = (h2o_accept_data_t *)sock->data;
    sock->data = NULL;
    h2o_iovec_t proto;

    if (status != 0) {
        h2o_socket_t::close(sock);
        goto Exit;
    }

    proto = sock->ssl_get_selected_protocol();
    const h2o_iovec_t *ident;
    for (ident = h2o_http2_alpn_protocols; ident->len != 0; ++ident) {
        if (proto.len == ident->len && memcmp(proto.base, ident->base, proto.len) == 0) {
            /* connect as http2 */
            h2o_http2_accept(data->ctx, sock, data->connected_at);
            goto Exit;
        }
    }
    /* connect as http1 */
    h2o_http1_accept(data->ctx, sock, data->connected_at);

Exit:
    free_accept_data(data);
}

static ssize_t parse_proxy_line(char *src, size_t len, struct sockaddr *sa, socklen_t *salen)
{
#define CHECK_EOF() \
    if (p == end)   \
    return -2
#define EXPECT_CHAR(ch)  \
    {                    \
        CHECK_EOF();     \
        if (*p++ != ch)  \
            return -1;   \
    }
#define SKIP_TO_WS()           \
    {                          \
        do {                   \
            CHECK_EOF();       \
        } while (*p++ != ' '); \
        --p;                   \
    }

    char *p = src, *end = p + len;
    void *addr;
    in_port_t *port;

    /* "PROXY "*/
    EXPECT_CHAR('P');
    EXPECT_CHAR('R');
    EXPECT_CHAR('O');
    EXPECT_CHAR('X');
    EXPECT_CHAR('Y');
    EXPECT_CHAR(' ');

    /* "TCP[46] " */
    CHECK_EOF();
    if (*p++ != 'T') {
        *salen = 0; /* indicate that no data has been obtained */
        goto SkipToEOL;
    }
    EXPECT_CHAR('C');
    EXPECT_CHAR('P');
    CHECK_EOF();
    switch (*p++) {
    case '4':
        *salen = sizeof(struct sockaddr_in);
        *((struct sockaddr_in *)sa) = {};
        sa->sa_family = AF_INET;
        addr = &((struct sockaddr_in *)sa)->sin_addr;
        port = &((struct sockaddr_in *)sa)->sin_port;
        break;
    case '6':
        *salen = sizeof(struct sockaddr_in6);
        *((struct sockaddr_in6 *)sa) = {};
        sa->sa_family = AF_INET6;
        addr = &((struct sockaddr_in6 *)sa)->sin6_addr;
        port = &((struct sockaddr_in6 *)sa)->sin6_port;
        break;
    default:
        return -1;
    }
    EXPECT_CHAR(' ');

    /* parse peer address */
    {
        char *addr_start = p;
        SKIP_TO_WS();
        *p = '\0';
        if (inet_pton(sa->sa_family, addr_start, addr) != 1)
            return -1;
        *p++ = ' ';
    }

    /* skip local address */
    SKIP_TO_WS();
    ++p;

    /* parse peer port */
    {
        char *port_start = p;
        SKIP_TO_WS();
        *p = '\0';
        unsigned short usval;
        if (sscanf(port_start, "%hu", &usval) != 1)
            return -1;
        *port = htons(usval);
        *p++ = ' ';
    }

SkipToEOL:
    do {
        CHECK_EOF();
    } while (*p++ != '\r');
    CHECK_EOF();
    if (*p++ != '\n')
        return -2;
    return p - src;

#undef CHECK_EOF
#undef EXPECT_CHAR
#undef SKIP_TO_WS
}

static void on_read_proxy_line(h2o_socket_t *sock, int status)
{
    auto data = (h2o_accept_data_t *)sock->data;

    if (status != 0) {
        free_accept_data(data);
        h2o_socket_t::close(sock);
        return;
    }

    struct sockaddr_storage addr;
    socklen_t addrlen;
    ssize_t r = parse_proxy_line(sock->input->bytes, sock->input->size, (sockaddr *)&addr, &addrlen);
    switch (r) {
    case -1: /* error, just pass the input to the next handler */
        break;
    case -2: /* incomplete */
        return;
    default:
        h2o_buffer_consume(&sock->input, r);
        if (addrlen != 0)
            sock->setpeername((sockaddr *)&addr, addrlen);
        break;
    }

    if (data->ctx->ssl_ctx != NULL) {
        sock->ssl_server_handshake(data->ctx->ssl_ctx, on_ssl_handshake_complete);
    } else {
        auto data = (h2o_accept_data_t *)sock->data;
        sock->data = NULL;
        h2o_http1_accept(data->ctx, sock, data->connected_at);
        free_accept_data(data);
    }
}

void h2o_accept(h2o_accept_ctx_t *ctx, h2o_socket_t *sock)
{
    struct timeval connected_at = *ctx->ctx->get_timestamp();

    if (ctx->expect_proxy_line || ctx->ssl_ctx != NULL) {
        create_accept_data(ctx, sock, connected_at);
        if (ctx->expect_proxy_line) {
            sock->read_start(on_read_proxy_line);
        } else {
            sock->ssl_server_handshake(ctx->ssl_ctx, on_ssl_handshake_complete);
        }
    } else {
        h2o_http1_accept(ctx, sock, connected_at);
    }
}

size_t h2o_stringify_protocol_version(char *dst, int version)
{
    char *p = dst;

    if (version < 0x200) {
        assert(version <= 0x109);
#define PREFIX "HTTP/1."
        memcpy(p, PREFIX, sizeof(PREFIX) - 1);
        p += sizeof(PREFIX) - 1;
#undef PREFIX
        *p++ = '0' + (version & 0xff);
    } else {
#define PROTO "HTTP/2"
        memcpy(p, PROTO, sizeof(PROTO) - 1);
        p += sizeof(PROTO) - 1;
#undef PROTO
    }

    *p = '\0';
    return p - dst;
}

h2o_iovec_t h2o_extract_push_path_from_link_header(
            h2o_mem_pool_t *pool, const char *value, size_t value_len,
            const h2o_url_scheme_t *base_scheme, h2o_iovec_t *base_authority,
            h2o_iovec_t *base_path)
{
    h2o_iovec_t url;
    h2o_url_t parsed, resolved;

    { /* extract URL value from: Link: </pushed.css>; rel=preload */
        h2o_iovec_t iter = h2o_iovec_t::create(value, value_len), token_value;
        const char *token;
        size_t token_len;
        /* first element should be <URL> */
        if ((token = h2o_next_token(&iter, ';', &token_len, NULL)) == NULL)
            goto None;
        if (!(token_len >= 2 && token[0] == '<' && token[token_len - 1] == '>'))
            goto None;
        url.init(token + 1, token_len - 2);
        /* find rel=preload */
        while ((token = h2o_next_token(&iter, ';', &token_len, &token_value)) != NULL) {
            if (h2o_lcstris(token, token_len, H2O_STRLIT("rel")) &&
                h2o_io_vector_literal_lcis(token_value, "preload"))
                break;
        }
        if (token == NULL)
            goto None;
    }

    /* check the authority, and extract absolute path */
    if (h2o_url_parse_relative_iov(url, &parsed) != 0)
        goto None;

    /* return the URL found in Link header, if it is an absolute path-only URL */
    if (parsed.scheme == NULL && parsed.authority.base == NULL && url.len != 0 && url.base[0] == '/')
        return h2o_strdup(pool, url.base, url.len);

    /* check scheme and authority if given URL contains either of the two */
    {
        h2o_url_t base = {base_scheme, *base_authority, {}, *base_path, H2O_PORT_NOT_SET};
        resolved.resolve(pool, &base, &parsed);
        if (base.scheme != resolved.scheme)
            goto None;
        if (parsed.authority.base != NULL &&
            !h2o_io_vector_lcis(base.authority, resolved.authority))
            goto None;
    }
    return resolved.path;

None:
    return {};
}

/* h2-14 and h2-16 are kept for backwards compatibility, as they are often used */
#define ALPN_ENTRY(s)    \
    {               \
        H2O_STRLIT(s)    \
    }
#define ALPN_PROTOCOLS_CORE ALPN_ENTRY("h2"), ALPN_ENTRY("h2-16"), ALPN_ENTRY("h2-14")
#define NPN_PROTOCOLS_CORE                                                                                                         \
    "\x02"          \
    "h2"            \
    "\x05"          \
    "h2-16"         \
    "\x05"          \
    "h2-14"

static const h2o_iovec_t http2_alpn_protocols[] = {ALPN_PROTOCOLS_CORE, {}};
const h2o_iovec_t *h2o_http2_alpn_protocols = http2_alpn_protocols;

static const h2o_iovec_t alpn_protocols[] = {ALPN_PROTOCOLS_CORE, {H2O_STRLIT("http/1.1")}, {}};
const h2o_iovec_t *h2o_alpn_protocols = alpn_protocols;

const char *h2o_http2_npn_protocols = NPN_PROTOCOLS_CORE;
const char *h2o_npn_protocols = NPN_PROTOCOLS_CORE "\x08" "http/1.1";

uint64_t h2o_connection_id = 0;
