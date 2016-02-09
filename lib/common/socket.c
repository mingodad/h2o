/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku, Justin Zhu
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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>
#include <openssl/err.h>
#include "h2o/socket.h"
#include "h2o/timeout.h"

#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#ifndef IOV_MAX
#define IOV_MAX UIO_MAXIOV
#endif
typedef enum {
        ASYNC_RESUMPTION_STATE_COMPLETE = 0, /* just pass thru */
        ASYNC_RESUMPTION_STATE_RECORD,       /* record first input and restore SSL state if state changes to REQUEST_SENT */
        ASYNC_RESUMPTION_STATE_REQUEST_SENT  /* async request has been sent, and is waiting for response */
    } H2o_ASYNC_RESUMPTION_STATE;
struct h2o_socket_ssl_t {
    SSL *ssl;
    int *did_write_in_read; /* used for detecting and closing the connection upon renegotiation (FIXME implement renegotiation) */
    struct {
        h2o_socket_cb cb;
        struct {
            H2o_ASYNC_RESUMPTION_STATE state;
            SSL_SESSION *session_data;
        } async_resumption;
    } handshake;
    struct {
        h2o_buffer_t *encrypted;
    } input;
    struct {
        H2O_VECTOR<h2o_iovec_t> bufs;
        h2o_mem_pool_t pool; /* placed at the last */
    } output;
};

struct h2o_ssl_context_t {
    SSL_CTX *ctx;
    const h2o_iovec_t *protocols;
    h2o_iovec_t _npn_list_of_protocols;
};

/* backend functions */
static void do_dispose_socket(h2o_socket_t *sock);
static void do_write(h2o_socket_t *sock, h2o_iovec_t *bufs, size_t bufcnt, h2o_socket_cb cb);
static void do_read_start(h2o_socket_t *sock);
static void do_read_stop(h2o_socket_t *sock);
static int do_export(h2o_socket_t *_sock, h2o_socket_export_t *info);
static h2o_socket_t *do_import(h2o_loop_t *loop, h2o_socket_export_t *info);
static socklen_t get_peername_uncached(h2o_socket_t *sock, struct sockaddr *sa);

/* internal functions called from the backend */
static int decode_ssl_input(h2o_socket_t *sock);
static void on_write_complete(h2o_socket_t *sock, int status);

#if H2O_USE_LIBUV
#include "socket/uv-binding.c.h"
#else
#include "socket/evloop.c.h"
#endif

h2o_buffer_mmap_settings_t h2o_socket_buffer_mmap_settings = {
    32 * 1024 * 1024, /* 32MB, should better be greater than max frame size of HTTP2 for performance reasons */
    "/tmp/h2o.b.XXXXXX"};

__thread h2o_buffer_prototype_t h2o_socket_buffer_prototype = {
    {16},                                       /* keep 16 recently used chunks */
    H2O_SOCKET_INITIAL_INPUT_BUFFER_SIZE * 2, /* minimum initial capacity */
    &h2o_socket_buffer_mmap_settings};

static void (*resumption_get_async)(h2o_socket_t *sock, h2o_iovec_t session_id);
static void (*resumption_new)(h2o_iovec_t session_id, h2o_iovec_t session_data);
static void (*resumption_remove)(h2o_iovec_t session_id);

static int read_bio(BIO *b, char *out, int len)
{
    auto sock = (h2o_socket_t *)b->ptr;
    auto &encrypted = sock->ssl->input.encrypted;

    if (len == 0)
        return 0;

    if (encrypted->size == 0) {
        BIO_set_retry_read(b);
        return -1;
    }

    if (encrypted->size < len) {
        len = (int)encrypted->size;
    }
    memcpy(out, encrypted->bytes, len);
    encrypted->consume(len);

    return len;
}

static int write_bio(BIO *b, const char *in, int len)
{
    auto sock = (h2o_socket_t *)b->ptr;
    void *bytes_alloced;

    /* FIXME no support for SSL renegotiation (yet) */
    if (sock->ssl->did_write_in_read != NULL) {
        *sock->ssl->did_write_in_read = 1;
        return -1;
    }

    if (len == 0)
        return 0;

    bytes_alloced = sock->ssl->output.pool.alloc(len);
    memcpy(bytes_alloced, in, len);

    sock->ssl->output.bufs.push_back(&sock->ssl->output.pool, h2o_iovec_t::create(bytes_alloced, len));

    return len;
}

static int puts_bio(BIO *b, const char *str)
{
    return write_bio(b, str, (int)strlen(str));
}

static long ctrl_bio(BIO *b, int cmd, long num, void *ptr)
{
    switch (cmd) {
    case BIO_CTRL_GET_CLOSE:
        return b->shutdown;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        return 1;
    case BIO_CTRL_FLUSH:
        return 1;
    default:
        return 0;
    }
}

static int new_bio(BIO *b)
{
    b->init = 0;
    b->num = 0;
    b->ptr = NULL;
    b->flags = 0;
    return 1;
}

static int free_bio(BIO *b)
{
    return b != NULL;
}

int decode_ssl_input(h2o_socket_t *sock)
{
    assert(sock->ssl != NULL);
    assert(sock->ssl->handshake.cb == NULL);

    while (sock->ssl->input.encrypted->size != 0 || SSL_pending(sock->ssl->ssl)) {
        int rlen;
        h2o_iovec_t buf = sock->input->reserve(4096); /*TODO remove magic numbers*/
        if (buf.base == NULL)
            return errno;
        { /* call SSL_read (while detecting SSL renegotiation and reporting it as error) */
            int did_write_in_read = 0;
            sock->ssl->did_write_in_read = &did_write_in_read;
            rlen = SSL_read(sock->ssl->ssl, buf.base, (int)buf.len);
            sock->ssl->did_write_in_read = NULL;
            if (did_write_in_read)
                return EIO;
        }
        if (rlen == -1) {
            if (SSL_get_error(sock->ssl->ssl, rlen) != SSL_ERROR_WANT_READ) {
                return EIO;
            }
            break;
        } else if (rlen == 0) {
            break;
        } else {
            sock->input->size += rlen;
        }
    }

    return 0;
}

static void flush_pending_ssl(h2o_socket_t *sock, h2o_socket_cb cb)
{
    do_write(sock, sock->ssl->output.bufs.entries, sock->ssl->output.bufs.size, cb);
}

static void clear_output_buffer(h2o_socket_ssl_t *ssl)
{
    h2o_clearmem(&ssl->output.bufs);
    ssl->output.pool.clear();
}

static void destroy_ssl(h2o_socket_ssl_t *ssl)
{
    SSL_free(ssl->ssl);
    ssl->ssl = NULL;
    h2o_buffer_t::dispose(ssl->input.encrypted);
    clear_output_buffer(ssl);
    h2o_mem_free(ssl);
}

static void dispose_socket(h2o_socket_t *sock, int status)
{
    void (*close_cb)(void *data);
    void *close_cb_data;

    if (sock->ssl != NULL) {
        destroy_ssl(sock->ssl);
        sock->ssl = NULL;
    }
    h2o_buffer_t::dispose(sock->input);
    if (sock->_peername != NULL) {
        h2o_mem_free(sock->_peername);
        sock->_peername = NULL;
    }

    close_cb = sock->on_close.cb;
    close_cb_data = sock->on_close.data;

    do_dispose_socket(sock);

    if (close_cb != NULL)
        close_cb(close_cb_data);
}

static void shutdown_ssl(h2o_socket_t *sock, int status)
{
    int ret;

    if (status != 0)
        goto Close;

    if (sock->_cb.write != NULL) {
        /* note: libuv calls the write callback after the socket is closed by uv_close (with status set to 0 if the write succeeded)
         */
        sock->_cb.write = NULL;
        goto Close;
    }

    if ((ret = SSL_shutdown(sock->ssl->ssl)) == -1) {
        goto Close;
    }

    if (sock->ssl->output.bufs.size != 0) {
        sock->read_stop();
        flush_pending_ssl(sock, ret == 1 ? dispose_socket : shutdown_ssl);
    } else if (ret == 2 && SSL_get_error(sock->ssl->ssl, ret) == SSL_ERROR_WANT_READ) {
        sock->read_start(shutdown_ssl);
    } else {
        status = ret == 1;
        goto Close;
    }

    return;
Close:
    dispose_socket(sock, status);
}

void h2o_socket_dispose_export(h2o_socket_export_t *info)
{
    assert(info->fd != -1);
    if (info->ssl != NULL) {
        destroy_ssl(info->ssl);
        info->ssl = NULL;
    }
    h2o_buffer_t::dispose(info->input);
    close(info->fd);
    info->fd = -1;
}

int h2o_socket_t::do_export(h2o_socket_export_t *info)
{
    static h2o_buffer_prototype_t nonpooling_prototype = {};

    assert(!this->is_writing());

    if (::do_export(this, info) == -1)
        return -1;

    if ((info->ssl = this->ssl) != NULL) {
        this->ssl = NULL;
        info->ssl->input.encrypted->set_prototype(&nonpooling_prototype);
    }
    info->input = this->input;
    info->input->set_prototype(&nonpooling_prototype);
    this->input->init(&h2o_socket_buffer_prototype);

    h2o_socket_t::close(this);

    return 0;
}

h2o_socket_t *h2o_socket_import(h2o_loop_t *loop, h2o_socket_export_t *info)
{
    h2o_socket_t *sock;

    assert(info->fd != -1);

    sock = do_import(loop, info);
    info->fd = -1; /* just in case */
    if ((sock->ssl = info->ssl) != NULL)
        sock->ssl->input.encrypted->set_prototype(&h2o_socket_buffer_prototype);
    sock->input = info->input;
    sock->input->set_prototype(&h2o_socket_buffer_prototype);
    return sock;
}

void h2o_socket_t::close(h2o_socket_t *sock)
{
    if (sock->ssl == NULL) {
        dispose_socket(sock, 0);
    } else {
        shutdown_ssl(sock, 0);
    }
}

void h2o_socket_t::write(h2o_iovec_t *bufs, size_t bufcnt, h2o_socket_cb cb)
{
#if H2O_SOCKET_DUMP_WRITE
    {
        size_t i;
        for (i = 0; i != bufcnt; ++i) {
            fprintf(stderr, "writing %zu bytes to fd:%d\n", bufs[i].len,
#if H2O_USE_LIBUV
                    ((struct st_h2o_uv_socket_t *)this)->uv.stream->io_watcher.fd
#else
                    ((h2o_evloop_socket_t *)this)->fd
#endif
                    );
            h2o_dump_memory(stderr, bufs[i].base, bufs[i].len);
        }
    }
#endif
    if (this->ssl == NULL) {
        do_write(this, bufs, bufcnt, cb);
    } else {
        assert(this->ssl->output.bufs.size == 0);
        /* fill in the data */
        for (; bufcnt != 0; ++bufs, --bufcnt) {
            size_t off = 0;
            while (off != bufs[0].len) {
                int ret;
                int sz = bufs[0].len - off;
                if (sz > 1400)
                    sz = 1400;
                ret = SSL_write(this->ssl->ssl, bufs[0].base + off, (int)sz);
                if (ret != sz) {
                    /* The error happens if SSL_write is called after SSL_read returns a fatal error (e.g. due to corrupt TCP packet
                     * being received). We need to take care of this since some protocol implementations send data after the read-
                     * side of the connection gets closed (note that protocol implementations are (yet) incapable of distinguishing
                     * a normal shutdown and close due to an error using the `status` value of the read callback).
                     */
                    clear_output_buffer(this->ssl);
                    flush_pending_ssl(this, cb);
#ifndef H2O_USE_LIBUV
                    ((h2o_evloop_socket_t *)this)->_flags |= H2O_SOCKET_FLAG_IS_WRITE_ERROR;
#endif
                    return;
                }
                off += sz;
            }
        }
        flush_pending_ssl(this, cb);
    }
}

void on_write_complete(h2o_socket_t *sock, int status)
{
    h2o_socket_cb cb;

    if (sock->ssl != NULL)
        clear_output_buffer(sock->ssl);

    cb = sock->_cb.write;
    sock->_cb.write = NULL;
    cb(sock, status);
}

void h2o_socket_t::read_start(h2o_socket_cb cb)
{
    this->_cb.read = cb;
    do_read_start(this);
}

void h2o_socket_t::read_stop()
{
    this->_cb.read = NULL;
    do_read_stop(this);
}

void h2o_socket_t::setpeername(struct sockaddr *sa, socklen_t len)
{
    if (this->_peername != NULL)
        h2o_mem_free(this->_peername);
    this->_peername = (h2o_socket_peername_t*)h2o_mem_alloc(offsetof(h2o_socket_peername_t, addr) + len);
    this->_peername->len = len;
    memcpy(&this->_peername->addr, sa, len);
}

socklen_t h2o_socket_t::getpeername(struct sockaddr *sa)
{
    /* return cached, if exists */
    if (this->_peername != NULL) {
        memcpy(sa, &this->_peername->addr, this->_peername->len);
        return this->_peername->len;
    }
    /* call, copy to cache, and return */
    socklen_t len = get_peername_uncached(this, sa);
    this->setpeername(sa, len);
    return len;
}

int h2o_socket_compare_address(struct sockaddr *x, struct sockaddr *y)
{
#define CMP(a, b)                                                                                                                  \
    if (a != b)                                                                                                                    \
    return a < b ? -1 : 1

    CMP(x->sa_family, y->sa_family);

    if (x->sa_family == AF_UNIX) {
        auto xun = (sockaddr_un *)x, yun = (sockaddr_un *)y;
        int r = strcmp(xun->sun_path, yun->sun_path);
        if (r != 0)
            return r;
    } else if (x->sa_family == AF_INET) {
        auto xin = (sockaddr_in *)x, yin = (sockaddr_in *)y;
        CMP(ntohl(xin->sin_addr.s_addr), ntohl(yin->sin_addr.s_addr));
        CMP(ntohs(xin->sin_port), ntohs(yin->sin_port));
    } else if (x->sa_family == AF_INET6) {
        auto xin6 = (sockaddr_in6 *)x, yin6 = (sockaddr_in6 *)y;
        int r = memcmp(xin6->sin6_addr.s6_addr, yin6->sin6_addr.s6_addr, sizeof(xin6->sin6_addr.s6_addr));
        if (r != 0)
            return r;
        CMP(ntohs(xin6->sin6_port), ntohs(yin6->sin6_port));
        CMP(xin6->sin6_flowinfo, yin6->sin6_flowinfo);
        CMP(xin6->sin6_scope_id, yin6->sin6_scope_id);
    } else {
        assert(!"unknown sa_family");
    }

#undef CMP
    return 0;
}

size_t h2o_socket_getnumerichost(struct sockaddr *sa, socklen_t salen, char *buf)
{
    if (sa->sa_family == AF_INET) {
        /* fast path for IPv4 addresses */
        auto sin = (sockaddr_in *)sa;
        uint32_t addr;
        addr = htonl(sin->sin_addr.s_addr);
        /*TODO change to snprintf*/
        return sprintf(buf, "%d.%d.%d.%d", addr >> 24, (addr >> 16) & 255, (addr >> 8) & 255, addr & 255);
    }

    if (getnameinfo(sa, salen, buf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0)
        return SIZE_MAX;
    return strlen(buf);
}

int32_t h2o_socket_getport(struct sockaddr *sa)
{
    switch (sa->sa_family) {
    case AF_INET:
        return htons(((struct sockaddr_in *)sa)->sin_port);
    case AF_INET6:
        return htons(((struct sockaddr_in6 *)sa)->sin6_port);
    default:
        return -1;
    }
}

static void create_ssl(h2o_socket_t *sock, SSL_CTX *ssl_ctx)
{
    static BIO_METHOD bio_methods = {BIO_TYPE_FD, "h2o_socket", write_bio, read_bio, puts_bio,
                                     NULL,        ctrl_bio,     new_bio,   free_bio, NULL};
    BIO *bio = BIO_new(&bio_methods);
    bio->ptr = sock;
    bio->init = 1;
    sock->ssl->ssl = SSL_new(ssl_ctx);
    SSL_set_bio(sock->ssl->ssl, bio, bio);
}

static SSL_SESSION *on_async_resumption_get(SSL *ssl, unsigned char *data, int len, int *copy)
{
    auto sock = (h2o_socket_t *)SSL_get_rbio(ssl)->ptr;
    auto &async_resumption = sock->ssl->handshake.async_resumption;

    switch (async_resumption.state) {
    case ASYNC_RESUMPTION_STATE_RECORD:
        async_resumption.state = ASYNC_RESUMPTION_STATE_REQUEST_SENT;
        resumption_get_async(sock, h2o_iovec_t::create(data, len));
        return NULL;
    case ASYNC_RESUMPTION_STATE_COMPLETE:
        *copy = 1;
        return async_resumption.session_data;
    default:
        assert(!"FIXME");
        return NULL;
    }
}

static int on_async_resumption_new(SSL *ssl, SSL_SESSION *session)
{
    h2o_iovec_t data;
    const unsigned char *id;
    unsigned id_len;
    unsigned char *p;

    /* build data */
    data.len = i2d_SSL_SESSION(session, NULL);
    data.base = (char*)h2o_mem_alloca(data.len);
    p = (unsigned char *)data.base;
    i2d_SSL_SESSION(session, &p);

    id = SSL_SESSION_get_id(session, &id_len);
    resumption_new(h2o_iovec_t::create(id, id_len), data);
    h2o_mem_alloca_free(data.base);
    return 0;
}

static void on_async_resumption_remove(SSL_CTX *ssl_ctx, SSL_SESSION *session)
{
    auto session_id = h2o_iovec_t::create(session->session_id, session->session_id_length);
    resumption_remove(session_id);
}

static void on_handshake_complete(h2o_socket_t *sock, int status)
{
    h2o_socket_cb handshake_cb = sock->ssl->handshake.cb;
    sock->_cb.write = NULL;
    sock->ssl->handshake.cb = NULL;
    decode_ssl_input(sock);
    handshake_cb(sock, status);
}

static void proceed_handshake(h2o_socket_t *sock, int status)
{
    h2o_iovec_t first_input = {};
    int ret;
    auto &encrypted = sock->ssl->input.encrypted;
    auto &async_resumption = sock->ssl->handshake.async_resumption;

    sock->_cb.write = NULL;

    if (status != 0) {
        goto Complete;
    }

    if (async_resumption.state == ASYNC_RESUMPTION_STATE_RECORD) {
        if (encrypted->size <= 1024) {
            /* retain a copy of input if performing async resumption */
            first_input.init(h2o_mem_alloca(encrypted->size), encrypted->size);
            memcpy(first_input.base, encrypted->bytes, first_input.len);
        } else {
            async_resumption.state = ASYNC_RESUMPTION_STATE_COMPLETE;
        }
    }

Redo:
    ret = SSL_accept(sock->ssl->ssl);

    switch (async_resumption.state) {
    case ASYNC_RESUMPTION_STATE_RECORD:
        /* async resumption has not been triggered; proceed the state to complete */
        async_resumption.state = ASYNC_RESUMPTION_STATE_COMPLETE;
        break;
    case ASYNC_RESUMPTION_STATE_REQUEST_SENT: {
        /* sent async request, reset the ssl state, and wait for async response */
        assert(ret < 0);
        SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(sock->ssl->ssl);
        SSL_free(sock->ssl->ssl);
        create_ssl(sock, ssl_ctx);
        clear_output_buffer(sock->ssl);
        encrypted->consume(encrypted->size);
        encrypted->append(first_input);
        sock->read_stop();
        goto CleanAlloca;
    }
    default:
        break;
    }

    if (ret == 0 || (ret < 0 && SSL_get_error(sock->ssl->ssl, ret) != SSL_ERROR_WANT_READ)) {
        /* failed */
        status = -1;
        goto Complete;
    }

    if (sock->ssl->output.bufs.size != 0) {
        sock->read_stop();
        flush_pending_ssl(sock, ret == 1 ? on_handshake_complete : proceed_handshake);
    } else {
        if (ret == 1) {
            goto Complete;
        }
        if (encrypted->size != 0)
            goto Redo;
        sock->read_start(proceed_handshake);
    }
    goto CleanAlloca;

Complete:
    sock->read_stop();
    on_handshake_complete(sock, status);
CleanAlloca:
    h2o_mem_alloca_free(first_input.base);
}

void h2o_socket_t::ssl_server_handshake(SSL_CTX *ssl_ctx, h2o_socket_cb handshake_cb)
{
    this->ssl = h2o_mem_calloc_for<h2o_socket_ssl_t>();

    /* setup the buffers; this->input should be empty, this->ssl->input.encrypted should contain the initial input, if any */
    this->ssl->input.encrypted->init(&h2o_socket_buffer_prototype);
    if (this->input->size != 0) {
        h2o_buffer_t *tmp = this->input;
        this->input = this->ssl->input.encrypted;
        this->ssl->input.encrypted = tmp;
    }

    this->ssl->output.pool.init();
    create_ssl(this, ssl_ctx);

    this->ssl->handshake.cb = handshake_cb;
    if (SSL_CTX_sess_get_get_cb(ssl_ctx) != NULL)
        this->ssl->handshake.async_resumption.state = ASYNC_RESUMPTION_STATE_RECORD;
    if (this->ssl->input.encrypted->size != 0)
        proceed_handshake(this, 0);
    else
        this->read_start(proceed_handshake);
}

void h2o_socket_t::ssl_resume_server_handshake(h2o_iovec_t session_data)
{
    auto &async_resumption = this->ssl->handshake.async_resumption;
    if (session_data.len != 0) {
        auto p = (const unsigned char *)session_data.base;
        async_resumption.session_data = d2i_SSL_SESSION(NULL, &p, (long)session_data.len);
        /* FIXME warn on failure */
    }

    async_resumption.state = ASYNC_RESUMPTION_STATE_COMPLETE;
    proceed_handshake(this, 0);

    if (async_resumption.session_data != NULL) {
        SSL_SESSION_free(async_resumption.session_data);
        async_resumption.session_data = NULL;
    }
}

void h2o_socket_ssl_async_resumption_init(h2o_socket_ssl_resumption_get_async_cb get_async_cb,
                                          h2o_socket_ssl_resumption_new_cb new_cb, h2o_socket_ssl_resumption_remove_cb remove_cb)
{
    resumption_get_async = get_async_cb;
    resumption_new = new_cb;
    resumption_remove = remove_cb;
}

void h2o_socket_ssl_async_resumption_setup_ctx(SSL_CTX *ctx)
{
    SSL_CTX_sess_set_get_cb(ctx, on_async_resumption_get);
    SSL_CTX_sess_set_new_cb(ctx, on_async_resumption_new);
    SSL_CTX_sess_set_remove_cb(ctx, on_async_resumption_remove);
    /* if necessary, it is the responsibility of the caller to disable the internal cache */
}

h2o_iovec_t h2o_socket_t::ssl_get_selected_protocol()
{
    const unsigned char *data = NULL;
    unsigned len = 0;

    assert(this->ssl != NULL);

#if H2O_USE_ALPN
    if (len == 0)
        SSL_get0_alpn_selected(this->ssl->ssl, &data, &len);
#endif
#if H2O_USE_NPN
    if (len == 0)
        SSL_get0_next_proto_negotiated(this->ssl->ssl, &data, &len);
#endif

    return h2o_iovec_t::create(data, len);
}

static int on_alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *_in, unsigned int inlen,
                          void *_protocols)
{
    auto protocols = (const h2o_iovec_t *)_protocols;
    size_t i;

    for (i = 0; protocols[i].len != 0; ++i) {
        const unsigned char *in = _in, *in_end = in + inlen;
        while (in != in_end) {
            size_t cand_len = *in++;
            if (in_end - in < cand_len) {
                /* broken request */
                return SSL_TLSEXT_ERR_NOACK;
            }
            if (cand_len == protocols[i].len && memcmp(in, protocols[i].base, cand_len) == 0) {
                goto Found;
            }
            in += cand_len;
        }
    }
    /* not found */
    return SSL_TLSEXT_ERR_NOACK;

Found:
    *out = (const unsigned char *)protocols[i].base;
    *outlen = (unsigned char)protocols[i].len;
    return SSL_TLSEXT_ERR_OK;
}

#if H2O_USE_ALPN

void h2o_ssl_register_alpn_protocols(SSL_CTX *ctx, const h2o_iovec_t *protocols)
{
    SSL_CTX_set_alpn_select_cb(ctx, on_alpn_select, (void *)protocols);
}

#endif

#if H2O_USE_NPN

static int on_npn_advertise(SSL *ssl, const unsigned char **out, unsigned *outlen, void *protocols)
{
    *out = (const unsigned char*)protocols;
    *outlen = (unsigned)strlen((const char*)protocols);
    return SSL_TLSEXT_ERR_OK;
}

void h2o_ssl_register_npn_protocols(SSL_CTX *ctx, const char *protocols)
{
    SSL_CTX_set_next_protos_advertised_cb(ctx, on_npn_advertise, (void *)protocols);
}

#endif
