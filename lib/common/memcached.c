/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
#include <inttypes.h>
#include <unistd.h>
#include "yrmcds.h"
#include "h2o/linklist.h"
#include "h2o/memcached.h"
#include "h2o/string_.h"

struct h2o_memcached_conn_t {
    h2o_memcached_context_t *ctx;
    yrmcds yrmcds;
    pthread_mutex_t mutex;
    h2o_linklist_t inflight;
    int writer_exit_requested;
};

enum en_h2o_memcached_req_type_t { REQ_TYPE_GET, REQ_TYPE_SET, REQ_TYPE_DELETE };

struct h2o_memcached_req_t {
    enum en_h2o_memcached_req_type_t type;
    h2o_linklist_t pending;
    h2o_linklist_t inflight;
    union {
        struct {
            h2o_multithread_receiver_t *receiver;
            h2o_multithread_message_t message;
            h2o_memcached_get_cb cb;
            void *cb_data;
            int value_is_encoded;
            h2o_iovec_t value;
            uint32_t serial;
        } get;
        struct {
            h2o_iovec_t value;
            uint32_t expiration;
        } set;
    } data;
    struct {
        size_t len;
        char base[1];
    } key;
};

static inline calcBase64EncodedSize(size_t unencoded_size)
{
    return (unencoded_size + 2) / 3 * 4 + 1;
}

static h2o_memcached_req_t *create_req(h2o_memcached_context_t *ctx, enum en_h2o_memcached_req_type_t type, h2o_iovec_t key,
                                       int encode_key)
{
    auto req = (h2o_memcached_req_t *)h2o_mem_alloc(offsetof(h2o_memcached_req_t, key.base) + ctx->prefix.len +
                                             (encode_key ? calcBase64EncodedSize(key.len) : key.len));
    req->type = type;
    req->pending = {};
    req->inflight = {};
    h2o_clearmem(&req->data);
    if (ctx->prefix.len != 0)
        memcpy(req->key.base, ctx->prefix.base, ctx->prefix.len);
    req->key.len = ctx->prefix.len;
    if (encode_key) {
        req->key.len += h2o_base64_encode(req->key.base + req->key.len, key.base, key.len, 1);
    } else {
        memcpy(req->key.base + req->key.len, key.base, key.len);
        req->key.len += key.len;
    }
    return req;
}

static void free_req(h2o_memcached_req_t *req)
{
    assert(!req->pending.is_linked());
    switch (req->type) {
    case REQ_TYPE_GET:
        assert(!req->data.get.message.link.is_linked());
        h2o_mem_free_secure(req->data.get.value);
        break;
    case REQ_TYPE_SET:
        h2o_mem_free_secure(req->data.set.value);
        break;
    case REQ_TYPE_DELETE:
        break;
    default:
        assert(!"FIXME");
        break;
    }
    h2o_mem_free(req);
}

static void discard_req(h2o_memcached_req_t *req)
{
    switch (req->type) {
    case REQ_TYPE_GET:
        req->data.get.receiver->send_message(&req->data.get.message);
        break;
    default:
        free_req(req);
        break;
    }
}

static h2o_memcached_req_t *pop_inflight(struct h2o_memcached_conn_t *conn, uint32_t serial)
{
    h2o_memcached_req_t *req;
    h2o_linklist_t *node;

    pthread_mutex_lock(&conn->mutex);

    for (node = conn->inflight.next; node != &conn->inflight; node = node->next) {
        req = H2O_STRUCT_FROM_MEMBER(h2o_memcached_req_t, inflight, node);
        assert(req->type == REQ_TYPE_GET);
        if (req->data.get.serial == serial) {
            req->inflight.unlink();
            goto Found;
        }
    }
    req = NULL;
Found:

    pthread_mutex_unlock(&conn->mutex);

    return req;
}

static void *writer_main(void *_conn)
{
    auto conn = (h2o_memcached_conn_t*)_conn;
    yrmcds_error err;

    pthread_mutex_lock(&conn->ctx->mutex);

    while (!__sync_add_and_fetch(&conn->writer_exit_requested, 0)) {
        while (!conn->ctx->pending.is_empty()) {
            auto req = H2O_STRUCT_FROM_MEMBER(h2o_memcached_req_t, pending, conn->ctx->pending.next);
            req->pending.unlink();
            pthread_mutex_unlock(&conn->ctx->mutex);

            switch (req->type) {
            case REQ_TYPE_GET:
                pthread_mutex_lock(&conn->mutex);
                conn->inflight.insert(&req->inflight);
                pthread_mutex_unlock(&conn->mutex);
                if ((err = yrmcds_get(&conn->yrmcds, req->key.base, req->key.len, 0, &req->data.get.serial)) != YRMCDS_OK)
                    goto Error;
                break;
            case REQ_TYPE_SET:
                if ((err = yrmcds_set(&conn->yrmcds, req->key.base, req->key.len, req->data.set.value.base, req->data.set.value.len,
                                      0, req->data.set.expiration, 0, 1, NULL)) != YRMCDS_OK)
                    goto Error;
                break;
            case REQ_TYPE_DELETE:
                if ((err = yrmcds_remove(&conn->yrmcds, req->key.base, req->key.len, 1, NULL)) != YRMCDS_OK)
                    goto Error;
                break;
            default:
                fprintf(stderr, "[lib/common/memcached.c] unknown type:%d\n", (int)req->type);
                err = YRMCDS_NOT_IMPLEMENTED;
                goto Error;
            }

            pthread_mutex_lock(&conn->ctx->mutex);
        }
        pthread_cond_wait(&conn->ctx->cond, &conn->ctx->mutex);
    }

    pthread_mutex_unlock(&conn->ctx->mutex);
    return NULL;

Error:
    fprintf(stderr, "[lib/common/memcached.c] failed to send request; %s\n", yrmcds_strerror(err));
    /* doc says the call can be used to interrupt yrmcds_recv */
    yrmcds_shutdown(&conn->yrmcds);

    return NULL;
}

static void connect_to_server(h2o_memcached_context_t *ctx, yrmcds *yrmcds)
{
    size_t failcnt;
    yrmcds_error err;

    for (failcnt = 0; (err = yrmcds_connect(yrmcds, ctx->host, ctx->port)) != YRMCDS_OK; ++failcnt) {
        if (failcnt == 0) {
            fprintf(stderr, "[lib/common/memcached.c] failed to connect to memcached at %s:%" PRIu16 ", %s\n", ctx->host, ctx->port,
                    yrmcds_strerror(err));
        }
        ++failcnt;
        usleep(2000000 + rand() % 3000000); /* sleep 2 to 5 seconds */
    }
    /* connected */
    fprintf(stderr, "[lib/common/memcached.c] connected to memcached at %s:%" PRIu16 "\n", ctx->host, ctx->port);
}

static void reader_main(h2o_memcached_context_t *ctx)
{
    struct h2o_memcached_conn_t conn = {ctx, {}, PTHREAD_MUTEX_INITIALIZER, {&conn.inflight, &conn.inflight}, 0};
    pthread_t writer_thread;
    yrmcds_response resp;
    yrmcds_error err;

    /* connect to server and start the writer thread */
    connect_to_server(conn.ctx, &conn.yrmcds);
    pthread_create(&writer_thread, NULL, writer_main, &conn);

    pthread_mutex_lock(&conn.ctx->mutex);
    ++conn.ctx->num_threads_connected;
    pthread_mutex_unlock(&conn.ctx->mutex);

    /* receive data until an error occurs */
    while (1) {
        if ((err = yrmcds_recv(&conn.yrmcds, &resp)) != YRMCDS_OK) {
            fprintf(stderr, "[lib/common/memcached.c] yrmcds_recv:%s\n", yrmcds_strerror(err));
            break;
        }
        h2o_memcached_req_t *req = pop_inflight(&conn, resp.serial);
        if (req == NULL) {
            fprintf(stderr, "[lib/common/memcached.c] received unexpected serial\n");
            break;
        }
        if (resp.status == YRMCDS_STATUS_OK) {
            req->data.get.value.init(h2o_mem_alloc(resp.data_len), resp.data_len);
            memcpy(req->data.get.value.base, resp.data, resp.data_len);
            h2o_mem_set_secure((void *)resp.data, 0, resp.data_len);
        }
        req->data.get.receiver->send_message(&req->data.get.message);
    }

    /* send error to all the reqs in-flight */
    pthread_mutex_lock(&conn.mutex);
    while (!conn.inflight.is_empty()) {
        auto req = H2O_STRUCT_FROM_MEMBER(h2o_memcached_req_t, inflight, conn.inflight.next);
        req->inflight.unlink();
        assert(req->type == REQ_TYPE_GET);
        req->data.get.receiver->send_message(&req->data.get.message);
    }
    pthread_mutex_unlock(&conn.mutex);

    /* stop the writer thread */
    __sync_add_and_fetch(&conn.writer_exit_requested, 1);
    pthread_mutex_lock(&conn.ctx->mutex);
    pthread_cond_broadcast(&conn.ctx->cond);
    pthread_mutex_unlock(&conn.ctx->mutex);
    pthread_join(writer_thread, NULL);

    /* decrement num_threads_connected, and discard all the pending requests if no connections are alive */
    pthread_mutex_lock(&conn.ctx->mutex);
    if (--conn.ctx->num_threads_connected == 0) {
        while (!conn.ctx->pending.is_empty()) {
            auto req = H2O_STRUCT_FROM_MEMBER(h2o_memcached_req_t, pending, conn.ctx->pending.next);
            req->pending.unlink();
            discard_req(req);
        }
    }
    pthread_mutex_unlock(&conn.ctx->mutex);

    /* close the connection */
    yrmcds_close(&conn.yrmcds);
}

static void *thread_main(void *_ctx)
{
    auto ctx = (h2o_memcached_context_t*)_ctx;

    while (1)
        reader_main(ctx);
    return NULL;
}

static void dispatch(h2o_memcached_context_t *ctx, h2o_memcached_req_t *req)
{
    pthread_mutex_lock(&ctx->mutex);

    if (ctx->num_threads_connected != 0) {
        ctx->pending.insert(&req->pending);
        pthread_cond_signal(&ctx->cond);
    } else {
        discard_req(req);
    }

    pthread_mutex_unlock(&ctx->mutex);
}

void h2o_memcached_receiver(h2o_multithread_receiver_t *receiver, h2o_linklist_t *messages)
{
    while (!messages->is_empty()) {
        auto req = H2O_STRUCT_FROM_MEMBER(h2o_memcached_req_t, data.get.message.link, messages->next);
        req->data.get.message.link.unlink();
        assert(req->type == REQ_TYPE_GET);
        if (req->data.get.cb != NULL) {
            if (req->data.get.value_is_encoded && req->data.get.value.len != 0) {
                h2o_iovec_t decoded = h2o_decode_base64url(req->data.get.value);
                h2o_mem_free_secure(req->data.get.value);
                req->data.get.value = decoded;
            }
            req->data.get.cb(req->data.get.value, req->data.get.cb_data);
        }
        free_req(req);
    }
}

h2o_memcached_req_t *h2o_memcached_context_t::get(h2o_multithread_receiver_t *receiver, h2o_iovec_t key,
                                       h2o_memcached_get_cb cb, void *cb_data, int flags)
{
    h2o_memcached_req_t *req = create_req(this, REQ_TYPE_GET, key, (flags & H2O_MEMCACHED_ENCODE_KEY) != 0);
    req->data.get.receiver = receiver;
    req->data.get.cb = cb;
    req->data.get.cb_data = cb_data;
    req->data.get.value_is_encoded = (flags & H2O_MEMCACHED_ENCODE_VALUE) != 0;
    dispatch(this, req);
    return req;
}

void h2o_memcached_context_t::cancel_get(h2o_memcached_req_t *req)
{
    int do_free = 0;

    pthread_mutex_lock(&this->mutex);
    req->data.get.cb = NULL;
    if (req->pending.is_linked()) {
        req->pending.unlink();
        do_free = 1;
    }
    pthread_mutex_unlock(&this->mutex);

    if (do_free)
        free_req(req);
}

void h2o_memcached_context_t::set(h2o_iovec_t key, h2o_iovec_t value, uint32_t expiration, int flags)
{
    h2o_memcached_req_t *req = create_req(this, REQ_TYPE_SET, key, (flags & H2O_MEMCACHED_ENCODE_KEY) != 0);
    if ((flags & H2O_MEMCACHED_ENCODE_VALUE) != 0) {
        req->data.set.value.base = h2o_mem_alloc_for<char>(calcBase64EncodedSize(value.len));
        req->data.set.value.len = h2o_base64_encode(req->data.set.value.base, value.base, value.len, 1);
    } else {
        req->data.set.value.init(h2o_mem_alloc(value.len), value.len);
        memcpy(req->data.set.value.base, value.base, value.len);
    }
    req->data.set.expiration = expiration;
    dispatch(this, req);
}

void h2o_memcached_context_t::remove(h2o_iovec_t key, int flags)
{
    h2o_memcached_req_t *req = create_req(this, REQ_TYPE_DELETE, key, (flags & H2O_MEMCACHED_ENCODE_KEY) != 0);
    dispatch(this, req);
}

h2o_memcached_context_t *h2o_memcached_context_t::create(const char *host, uint16_t port, size_t num_threads, const char *prefix)
{
    auto ctx = h2o_mem_alloc_for<h2o_memcached_context_t>();

    pthread_mutex_init(&ctx->mutex, NULL);
    pthread_cond_init(&ctx->cond, NULL);
    ctx->pending.init_anchor();
    ctx->num_threads_connected = 0;
    ctx->host = h2o_strdup(NULL, host, SIZE_MAX).base;
    ctx->port = port;
    ctx->prefix = h2o_strdup(NULL, prefix, SIZE_MAX);

    { /* start the threads */
        pthread_t tid;
        pthread_attr_t attr;
        size_t i;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, 1);
        for (i = 0; i != num_threads; ++i)
            h2o_multithread_create_thread(&tid, &attr, thread_main, ctx);
        pthread_attr_destroy(&attr);
    }

    return ctx;
}
