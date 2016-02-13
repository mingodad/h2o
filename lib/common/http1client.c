/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include "picohttpparser.h"
#include "h2o/string_.h"
#include "h2o/hostinfo.h"
#include "h2o/http1client.h"
#include "h2o/url.h"

struct h2o_http1client_private_t {
    h2o_http1client_t super;
    union {
        h2o_http1client_connect_cb on_connect;
        h2o_http1client_head_cb on_head;
        h2o_http1client_body_cb on_body;
    } _cb;
    h2o_timeout_entry_t _timeout;
    int _method_is_head;
    h2o_hostinfo_getaddr_req_t *_getaddr_req;
    int _can_keepalive;
    union {
        struct {
            size_t bytesleft;
        } content_length;
        struct {
            phr_chunked_decoder decoder;
            size_t bytes_decoded_in_buf;
        } chunked;
    } _body_decoder;
};

static inline void h2o_timeout_link(h2o_http1client_private_t *client)
{
    client->super.ctx->io_timeout->link(client->super.ctx->loop, &client->_timeout);
}

static void close_client(h2o_http1client_private_t *client)
{
    if (client->_getaddr_req != NULL) {
        h2o_hostinfo_getaddr_cancel(client->_getaddr_req);
        client->_getaddr_req = NULL;
    }
    h2o_socket_t *sock = client->super.sock;
    socketpool_t *sockpool = &client->super.sockpool;
    if (sock != NULL) {
        if (sockpool->pool != NULL && client->_can_keepalive) {
            /* we do not send pipelined requests, and thus can trash all the received input at the end of the request */
            h2o_buffer_consume_all(&sock->input);
            h2o_socketpool_return(sockpool->pool, sock);
        } else {
            h2o_socket_t::close(sock);
        }
    } else {
        if (sockpool->connect_req != NULL) {
            h2o_socketpool_cancel_connect(sockpool->connect_req);
            sockpool->connect_req = NULL;
        }
    }
    client->_timeout.unlink();
    h2o_mem_free(client);
}

static void on_body_error(h2o_http1client_private_t *client, const char *errstr)
{
    client->_can_keepalive = 0;
    client->_cb.on_body(&client->super, errstr);
    close_client(client);
}

static void on_body_timeout(h2o_timeout_entry_t *entry)
{
    auto client = H2O_STRUCT_FROM_MEMBER(h2o_http1client_private_t, _timeout, entry);
    on_body_error(client, "I/O timeout");
}

static void on_body_until_close(h2o_socket_t *sock, int status)
{
    auto client = (h2o_http1client_private_t*)sock->data;

    client->_timeout.unlink();

    if (status != 0) {
        client->_cb.on_body(&client->super, h2o_http1client_error_is_eos);
        close_client(client);
        return;
    }

    if (sock->bytes_read != 0) {
        if (client->_cb.on_body(&client->super, NULL) != 0) {
            close_client(client);
            return;
        }
    }

    h2o_timeout_link(client);
}

static void on_body_content_length(h2o_socket_t *sock, int status)
{
    auto client = (h2o_http1client_private_t*)sock->data;

    client->_timeout.unlink();

    if (status != 0) {
        on_body_error(client, "I/O error (body; content-length)");
        return;
    }

    auto &bytesleft = client->_body_decoder.content_length.bytesleft;
    if (sock->bytes_read != 0 || bytesleft == 0) {
        const char *errstr;
        int ret;
        if (bytesleft <= sock->bytes_read) {
            if (bytesleft < sock->bytes_read) {
                /* remove the trailing garbage from buf, and disable keepalive */
                client->super.sock->input->size -= sock->bytes_read - bytesleft;
                client->_can_keepalive = 0;
            }
            bytesleft = 0;
            errstr = h2o_http1client_error_is_eos;
        } else {
            bytesleft -= sock->bytes_read;
            errstr = NULL;
        }
        ret = client->_cb.on_body(&client->super, errstr);
        if (errstr == h2o_http1client_error_is_eos) {
            close_client(client);
            return;
        } else if (ret != 0) {
            client->_can_keepalive = 0;
            close_client(client);
            return;
        }
    }

    h2o_timeout_link(client);
}

static void on_body_chunked(h2o_socket_t *sock, int status)
{
    auto client = (h2o_http1client_private_t*)sock->data;
    h2o_buffer_t *inbuf;

    client->_timeout.unlink();

    if (status != 0) {
        on_body_error(client, "I/O error (body; chunked)");
        return;
    }

    inbuf = client->super.sock->input;
    if (sock->bytes_read != 0) {
        const char *errstr;
        int cb_ret;
        size_t newsz = sock->bytes_read;
        switch (phr_decode_chunked(&client->_body_decoder.chunked.decoder, inbuf->bytes + inbuf->size - newsz, &newsz)) {
        case -1: /* error */
            newsz = sock->bytes_read;
            client->_can_keepalive = 0;
            errstr = "failed to parse the response (chunked)";
            break;
        case -2: /* incomplete */
            errstr = NULL;
            break;
        default: /* complete, with garbage on tail; should disable keepalive */
            client->_can_keepalive = 0;
        /* fallthru */
        case 0: /* complete */
            errstr = h2o_http1client_error_is_eos;
            break;
        }
        inbuf->size -= sock->bytes_read - newsz;
        cb_ret = client->_cb.on_body(&client->super, errstr);
        if (errstr != NULL) {
            close_client(client);
            return;
        } else if (cb_ret != 0) {
            client->_can_keepalive = 0;
            close_client(client);
            return;
        }
    }

    h2o_timeout_link(client);
}

static void on_error_before_head(h2o_http1client_private_t *client, const char *errstr)
{
    assert(!client->_can_keepalive);
    client->_cb.on_head(&client->super, errstr, 0, 0, h2o_iovec_t::create(nullptr, 0), NULL, 0);
    close_client(client);
}

static void on_head(h2o_socket_t *sock, int status)
{
    auto client = (h2o_http1client_private_t*)sock->data;
    int minor_version, http_status, rlen, is_eos;
    const char *msg;
    struct phr_header headers[100];
    size_t msg_len, num_headers, i;
    h2o_socket_cb reader;

    client->_timeout.unlink();

    if (status != 0) {
        on_error_before_head(client, "I/O error (head)");
        return;
    }

    /* parse response */
    num_headers = sizeof(headers) / sizeof(headers[0]);
    rlen = phr_parse_response(sock->input->bytes, sock->input->size, &minor_version, &http_status, &msg, &msg_len, headers,
                              &num_headers, 0);
    switch (rlen) {
    case -1: /* error */
        on_error_before_head(client, "failed to parse the response");
        return;
    case -2: /* incomplete */
        h2o_timeout_link(client);
        return;
    }

    /* parse the headers */
    reader = on_body_until_close;
    client->_can_keepalive = minor_version >= 1;
    for (i = 0; i != num_headers; ++i) {
        auto &hdr = headers[i];
        h2o_phr_headertolower(hdr);
        if (h2o_phr_header_name_is_literal(hdr, "connection")) {
            if (h2o_contains_token(hdr.value, hdr.value_len, H2O_STRLIT("keep-alive"), ',')) {
                client->_can_keepalive = 1;
            } else {
                client->_can_keepalive = 0;
            }
        } else if (h2o_phr_header_name_is_literal(hdr, "transfer-encoding")) {
            if (h2o_phr_header_value_is_literal(hdr, "chunked")) {
                /* precond: _body_decoder.chunked is zero-filled */
                client->_body_decoder.chunked.decoder.consume_trailer = 1;
                reader = on_body_chunked;
            } else if (h2o_phr_header_value_is_literal(hdr, "identity")) {
                /* continue */
            } else {
                on_error_before_head(client, "unexpected type of transfer-encoding");
                return;
            }
        } else if (h2o_phr_header_name_is_literal(hdr, "content-length")) {
            if ((client->_body_decoder.content_length.bytesleft = h2o_pht_header_value_tosize(hdr)) ==
                SIZE_MAX) {
                on_error_before_head(client, "invalid content-length");
                return;
            }
            if (reader != on_body_chunked)
                reader = on_body_content_length;
        }
    }

    /* RFC 2616 4.4 */
    if (client->_method_is_head || ((100 <= http_status && http_status <= 199) || http_status == 204 || http_status == 304)) {
        is_eos = 1;
    } else {
        is_eos = 0;
        /* close the connection if impossible to determine the end of the response (RFC 7230 3.3.3) */
        if (reader == on_body_until_close)
            client->_can_keepalive = 0;
    }

    /* call the callback */
    client->_cb.on_body = client->_cb.on_head(&client->super, is_eos ? h2o_http1client_error_is_eos : NULL, minor_version,
                                              http_status, h2o_iovec_t::create(msg, msg_len), headers, num_headers);
    if (is_eos) {
        close_client(client);
        return;
    } else if (client->_cb.on_body == NULL) {
        client->_can_keepalive = 0;
        close_client(client);
        return;
    }

    h2o_buffer_consume(&client->super.sock->input, rlen);
    client->super.sock->bytes_read = client->super.sock->input->size;

    client->_timeout.cb = on_body_timeout;
    sock->read_start(reader);
    reader(client->super.sock, 0);
}

static void on_head_timeout(h2o_timeout_entry_t *entry)
{
    auto client = H2O_STRUCT_FROM_MEMBER(h2o_http1client_private_t, _timeout, entry);
    on_error_before_head(client, "I/O timeout");
}

static void on_send_request(h2o_socket_t *sock, int status)
{
    auto client = (h2o_http1client_private_t*)sock->data;

    client->_timeout.unlink();

    if (status != 0) {
        on_error_before_head(client, "I/O error (send request)");
        return;
    }

    client->super.sock->read_start(on_head);
    client->_timeout.cb = on_head_timeout;
    h2o_timeout_link(client);
}

static void on_send_timeout(h2o_timeout_entry_t *entry)
{
    auto client = H2O_STRUCT_FROM_MEMBER(h2o_http1client_private_t, _timeout, entry);
    on_error_before_head(client, "I/O timeout");
}

static void on_connect_error(h2o_http1client_private_t *client, const char *errstr)
{
    assert(errstr != NULL);
    client->_cb.on_connect(&client->super, errstr, NULL, NULL, NULL);
    close_client(client);
}

static void on_connect(h2o_socket_t *sock, int status)
{
    auto client = (h2o_http1client_private_t*)sock->data;
    h2o_iovec_t *reqbufs;
    size_t reqbufcnt;

    client->_timeout.unlink();

    if (status != 0) {
        on_connect_error(client, "connection failed");
        return;
    }

    if ((client->_cb.on_head = client->_cb.on_connect(&client->super, NULL, &reqbufs, &reqbufcnt, &client->_method_is_head)) ==
        NULL) {
        close_client(client);
        return;
    }
    client->super.sock->write(reqbufs, reqbufcnt, on_send_request);
    /* TODO no need to set the timeout if all data has been written into TCP sendbuf */
    client->_timeout.cb = on_send_timeout;
    h2o_timeout_link(client);
}

static void on_pool_connect(h2o_socket_t *sock, const char *errstr, void *data)
{
    auto client = (h2o_http1client_private_t*)data;

    client->super.sockpool.connect_req = NULL;

    if (sock == NULL) {
        assert(errstr != NULL);
        on_connect_error(client, errstr);
        return;
    }

    client->super.sock = sock;
    sock->data = client;
    on_connect(sock, 0);
}

static void on_connect_timeout(h2o_timeout_entry_t *entry)
{
    auto client = H2O_STRUCT_FROM_MEMBER(h2o_http1client_private_t, _timeout, entry);
    on_connect_error(client, "connection timeout");
}

static void start_connect(h2o_http1client_private_t *client, struct sockaddr *addr, socklen_t addrlen)
{
    if ((client->super.sock = h2o_socket_connect(client->super.ctx->loop, addr, addrlen, on_connect)) == NULL) {
        on_connect_error(client, "socket create error");
        return;
    }
    client->super.sock->data = client;
}

static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *errstr, struct addrinfo *res, void *_client)
{
    auto client = (h2o_http1client_private_t*)_client;

    assert(getaddr_req == client->_getaddr_req);
    client->_getaddr_req = NULL;

    if (errstr != NULL) {
        on_connect_error(client, errstr);
        return;
    }

    /* start connecting */
    struct addrinfo *selected = h2o_hostinfo_select_one(res);
    start_connect(client, selected->ai_addr, selected->ai_addrlen);
}

static h2o_http1client_private_t *create_client(h2o_http1client_t **_client, void *data, h2o_http1client_ctx_t *ctx,
                                                          h2o_http1client_connect_cb cb)
{
    auto client = h2o_mem_alloc_for<h2o_http1client_private_t>();

    *client = (h2o_http1client_private_t){{ctx}};
    if (_client != NULL)
        *_client = &client->super;
    client->super.data = data;
    client->_cb.on_connect = cb;
    /* caller needs to setup _cb, timeout.cb, sock, and sock->data */

    return client;
}

const char *const h2o_http1client_error_is_eos = "end of stream";

void h2o_http1client_t::connect(h2o_http1client_t **_client, void *data, h2o_http1client_ctx_t *ctx, h2o_iovec_t host, uint16_t port,
                             h2o_http1client_connect_cb cb)
{
    h2o_http1client_private_t *client;
    char serv[sizeof("65536")];

    /* setup */
    client = create_client(_client, data, ctx, cb);
    client->_timeout.cb = on_connect_timeout;
    h2o_timeout_link(client);

    { /* directly call connect(2) if `host` is an IP address */
        struct sockaddr_in sin = {};
        if (h2o_hostinfo_aton(host, &sin.sin_addr) == 0) {
            sin.sin_family = AF_INET;
            sin.sin_port = htons(port);
            start_connect(client, (sockaddr*)&sin, sizeof(sin));
            return;
        }
    }
    { /* directly call connect(2) if `host` refers to an UNIX-domain socket */
        struct sockaddr_un sa;
        const char *to_sa_err;
        if ((to_sa_err = h2o_url_host_to_sun(host, &sa)) != h2o_url_host_to_sun_err_is_not_unix_socket) {
            if (to_sa_err != NULL) {
                on_connect_error(client, to_sa_err);
                return;
            }
            start_connect(client, (sockaddr*)&sa, sizeof(sa));
            return;
        }
    }
    /* resolve destination and then connect */
    client->_getaddr_req =
        h2o_hostinfo_getaddr(ctx->getaddr_receiver, host,
                             h2o_iovec_t::create(serv, snprintf(serv, sizeof(serv), "%u", (unsigned)port)),
                             on_getaddr, client);
}

void h2o_http1client_t::connect_with_pool(h2o_http1client_t **_client, void *data, h2o_http1client_ctx_t *ctx,
                                       h2o_socketpool_t *sockpool, h2o_http1client_connect_cb cb)
{
    h2o_http1client_private_t *client = create_client(_client, data, ctx, cb);
    client->super.sockpool.pool = sockpool;
    client->_timeout.cb = on_connect_timeout;
    h2o_timeout_link(client);
    h2o_socketpool_connect(&client->super.sockpool.connect_req, sockpool, ctx->loop, ctx->getaddr_receiver, on_pool_connect,
                           client);
}

void h2o_http1client_t::cancel()
{
    auto client = (h2o_http1client_private_t*)this;
    client->_can_keepalive = 0;
    close_client(client);
}

h2o_socket_t *h2o_http1client_t::steal_socket()
{
    auto client = (h2o_http1client_private_t*)this;
    h2o_socket_t *sock = client->super.sock;
    sock->read_stop();
    client->super.sock = NULL;
    return sock;
}
