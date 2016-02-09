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
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "h2o/hostinfo.h"
#include "h2o/linklist.h"
#include "h2o/socketpool.h"
#include "h2o/string_.h"
#include "h2o/timeout.h"

struct pool_entry_t {
    h2o_socket_export_t sockinfo;
    h2o_linklist_t link;
    uint64_t added_at;
};

struct st_h2o_socketpool_connect_request_t {
    void *data;
    h2o_socketpool_connect_cb cb;
    h2o_socketpool_t *pool;
    h2o_loop_t *loop;
    h2o_hostinfo_getaddr_req_t *getaddr_req;
    h2o_socket_t *sock;
};

static void destroy_detached(struct pool_entry_t *entry)
{
    h2o_socket_dispose_export(&entry->sockinfo);
    h2o_mem_free(entry);
}

static void destroy_attached(struct pool_entry_t *entry)
{
    entry->link.unlink();
    destroy_detached(entry);
}

static void destroy_expired(h2o_socketpool_t *pool)
{
    /* caller should lock the mutex */
    uint64_t expire_before = h2o_now(pool->_interval_cb.loop) - pool->timeout;
    while (!pool->_shared.sockets.is_empty()) {
        auto entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, link, pool->_shared.sockets.next);
        if (entry->added_at > expire_before)
            break;
        destroy_attached(entry);
        __sync_sub_and_fetch(&pool->_shared.count, 1);
    }
}

static void on_timeout(h2o_timeout_entry_t *timeout_entry)
{
    /* FIXME decrease the frequency of this function being called; the expiration
     * check can be (should be) performed in the `connect` fuction as well
     */
    auto pool = H2O_STRUCT_FROM_MEMBER(h2o_socketpool_t, _interval_cb.entry, timeout_entry);

    if (pthread_mutex_trylock(&pool->_shared.mutex) == 0) {
        destroy_expired(pool);
        pthread_mutex_unlock(&pool->_shared.mutex);
    }

    pool->_interval_cb.timeout.link(pool->_interval_cb.loop, &pool->_interval_cb.entry);
}

static void common_init(h2o_socketpool_t *pool, h2o_socketpool_type_t type, size_t capacity)
{
    h2o_clearmem(pool);

    pool->type = type;
    pool->capacity = capacity;
    pool->timeout = UINT64_MAX;

    pthread_mutex_init(&pool->_shared.mutex, NULL);
    pool->_shared.sockets.init_anchor();
}

void h2o_socketpool_init_by_address(h2o_socketpool_t *pool, struct sockaddr *sa, socklen_t salen, size_t capacity)
{
    assert(salen <= sizeof(pool->peer.sockaddr.bytes));

    common_init(pool, H2O_SOCKETPOOL_TYPE_SOCKADDR, capacity);
    memcpy(&pool->peer.sockaddr.bytes, sa, salen);
    pool->peer.sockaddr.len = salen;
}

void h2o_socketpool_init_by_hostport(h2o_socketpool_t *pool, h2o_iovec_t host, uint16_t port, size_t capacity)
{
    struct sockaddr_in sin = {};

    if (h2o_hostinfo_aton(host, &sin.sin_addr) == 0) {
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        h2o_socketpool_init_by_address(pool, (sockaddr *)&sin, sizeof(sin), capacity);
        return;
    }

    common_init(pool, H2O_SOCKETPOOL_TYPE_NAMED, capacity);
    pool->peer.named.host.strdup(host);
    size_t port_size = sizeof("65535");
    pool->peer.named.port.base = h2o_mem_alloc_for<char>(port_size);
    pool->peer.named.port.len = snprintf(pool->peer.named.port.base, port_size, "%u", (unsigned)port);
}

void h2o_socketpool_dispose(h2o_socketpool_t *pool)
{
    pthread_mutex_lock(&pool->_shared.mutex);
    while (!pool->_shared.sockets.is_empty()) {
        auto entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, link, pool->_shared.sockets.next);
        destroy_attached(entry);
        __sync_sub_and_fetch(&pool->_shared.count, 1);
    }
    pthread_mutex_unlock(&pool->_shared.mutex);
    pthread_mutex_destroy(&pool->_shared.mutex);

    if (pool->_interval_cb.loop != NULL) {
        pool->_interval_cb.entry.unlink();
        h2o_timeout_t::dispose(pool->_interval_cb.loop, &pool->_interval_cb.timeout);
    }
    switch (pool->type) {
    case H2O_SOCKETPOOL_TYPE_NAMED:
        h2o_mem_free(pool->peer.named.host.base);
        h2o_mem_free(pool->peer.named.port.base);
        break;
    case H2O_SOCKETPOOL_TYPE_SOCKADDR:
        break;
    }
}

void h2o_socketpool_set_timeout(h2o_socketpool_t *pool, h2o_loop_t *loop, uint64_t msec)
{
    pool->timeout = msec;

    pool->_interval_cb.loop = loop;
    pool->_interval_cb.timeout.init(loop, 1000);
    pool->_interval_cb.entry.cb = on_timeout;

    pool->_interval_cb.timeout.link(loop, &pool->_interval_cb.entry);
}

static void call_connect_cb(h2o_socketpool_connect_request_t *req, const char *errstr)
{
    h2o_socketpool_connect_cb cb = req->cb;
    h2o_socket_t *sock = req->sock;
    void *data = req->data;

    h2o_mem_free(req);
    cb(sock, errstr, data);
}

static void on_connect(h2o_socket_t *sock, int status)
{
    auto req = (h2o_socketpool_connect_request_t *)sock->data;
    const char *errstr = NULL;

    assert(req->sock == sock);

    if (status != 0) {
        h2o_socket_t::close(sock);
        req->sock = NULL;
        errstr = "connection failed";
    }
    call_connect_cb(req, errstr);
}

static void on_close(void *data)
{
    auto pool = (h2o_socketpool_t *)data;
    __sync_sub_and_fetch(&pool->_shared.count, 1);
}

static void start_connect(h2o_socketpool_connect_request_t *req, struct sockaddr *addr, socklen_t addrlen)
{
    req->sock = h2o_socket_connect(req->loop, addr, addrlen, on_connect);
    if (req->sock == NULL) {
        __sync_sub_and_fetch(&req->pool->_shared.count, 1);
        call_connect_cb(req, "failed to connect to host");
        return;
    }
    req->sock->data = req;
    req->sock->on_close.cb = on_close;
    req->sock->on_close.data = req->pool;
}

static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *errstr, struct addrinfo *res, void *_req)
{
    auto req = (h2o_socketpool_connect_request_t *)_req;

    assert(getaddr_req == req->getaddr_req);
    req->getaddr_req = NULL;

    if (errstr != NULL) {
        __sync_sub_and_fetch(&req->pool->_shared.count, 1);
        call_connect_cb(req, errstr);
        return;
    }

    struct addrinfo *selected = h2o_hostinfo_select_one(res);
    start_connect(req, selected->ai_addr, selected->ai_addrlen);
}

void h2o_socketpool_connect(h2o_socketpool_connect_request_t **_req, h2o_socketpool_t *pool, h2o_loop_t *loop,
                            h2o_multithread_receiver_t *getaddr_receiver, h2o_socketpool_connect_cb cb, void *data)
{
    struct pool_entry_t *entry = NULL;

    if (_req != NULL)
        *_req = NULL;

    /* fetch an entry and return it */
    pthread_mutex_lock(&pool->_shared.mutex);
    destroy_expired(pool);
    while (1) {
        if (pool->_shared.sockets.is_empty())
            break;
        entry = H2O_STRUCT_FROM_MEMBER(struct pool_entry_t, link, pool->_shared.sockets.next);
        entry->link.unlink();
        pthread_mutex_unlock(&pool->_shared.mutex);

        /* test if the connection is still alive */
        char buf[1];
        ssize_t rret = recv(entry->sockinfo.fd, buf, 1, MSG_PEEK);
        if (rret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            /* yes! return it */
            h2o_socket_t *sock = h2o_socket_import(loop, &entry->sockinfo);
            h2o_mem_free(entry);
            sock->on_close.cb = on_close;
            sock->on_close.data = pool;
            cb(sock, NULL, data);
            return;
        }

        /* connection is dead, report, close, and retry */
        if (rret <= 0) {
            static long counter = 0;
            if (__sync_fetch_and_add(&counter, 1) == 0)
                fprintf(stderr, "[WARN] detected close by upstream before the expected timeout (see issue #679)\n");
        } else {
            static long counter = 0;
            if (__sync_fetch_and_add(&counter, 1) == 0)
                fprintf(stderr, "[WARN] unexpectedly received data to a pooled socket (see issue #679)\n");
        }
        destroy_detached(entry);
        pthread_mutex_lock(&pool->_shared.mutex);
    }
    pthread_mutex_unlock(&pool->_shared.mutex);

    /* FIXME repsect `capacity` */
    __sync_add_and_fetch(&pool->_shared.count, 1);

    /* prepare request object */
    auto req = h2o_mem_alloc_for<h2o_socketpool_connect_request_t>();
    *req = (h2o_socketpool_connect_request_t){data, cb, pool, loop};
    if (_req != NULL)
        *_req = req;

    switch (pool->type) {
    case H2O_SOCKETPOOL_TYPE_NAMED:
        /* resolve the name, and connect */
        req->getaddr_req = h2o_hostinfo_getaddr(getaddr_receiver, pool->peer.named.host, pool->peer.named.port,
                                                on_getaddr, req);
        break;
    case H2O_SOCKETPOOL_TYPE_SOCKADDR:
        /* connect (using sockaddr_in) */
        start_connect(req, (sockaddr *)&pool->peer.sockaddr.bytes, pool->peer.sockaddr.len);
        break;
    }
}

void h2o_socketpool_cancel_connect(h2o_socketpool_connect_request_t *req)
{
    if (req->getaddr_req != NULL) {
        h2o_hostinfo_getaddr_cancel(req->getaddr_req);
        req->getaddr_req = NULL;
    }
    if (req->sock != NULL)
        h2o_socket_t::close(req->sock);
    h2o_mem_free(req);
}

int h2o_socketpool_return(h2o_socketpool_t *pool, h2o_socket_t *sock)
{
    /* reset the on_close callback */
    assert(sock->on_close.data == pool);
    sock->on_close.cb = NULL;
    sock->on_close.data = NULL;

    auto entry = h2o_mem_alloc_for<pool_entry_t>();
    if (sock->do_export(&entry->sockinfo) != 0) {
        h2o_mem_free(entry);
        __sync_sub_and_fetch(&pool->_shared.count, 1);
        return -1;
    }
    h2o_clearmem(&entry->link);
    entry->added_at = h2o_now(h2o_socket_get_loop(sock));

    pthread_mutex_lock(&pool->_shared.mutex);
    destroy_expired(pool);
    pool->_shared.sockets.insert(&entry->link);
    pthread_mutex_unlock(&pool->_shared.mutex);

    return 0;
}
