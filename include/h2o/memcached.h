/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku
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
#ifndef h2o__memcached_h
#define h2o__memcached_h

#include <pthread.h>
#include "h2o/memory.h"
#include "h2o/multithread.h"

#define H2O_MEMCACHED_ENCODE_KEY 0x1
#define H2O_MEMCACHED_ENCODE_VALUE 0x2

typedef void (*h2o_memcached_get_cb)(h2o_iovec_t value, void *cb_data);
struct h2o_memcached_req_t;

struct h2o_memcached_context_t {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    h2o_linklist_t pending;
    size_t num_threads_connected;
    char *host;
    uint16_t port;
    h2o_iovec_t prefix;

    static h2o_memcached_context_t *create(const char *host, uint16_t port, size_t num_threads, const char *prefix);
    h2o_memcached_req_t *get(h2o_multithread_receiver_t *receiver, h2o_iovec_t key,
                                           h2o_memcached_get_cb cb, void *cb_data, int flags);

    void cancel_get(h2o_memcached_req_t *req);

    void set(h2o_iovec_t key, h2o_iovec_t value, uint32_t expiration, int flags);

    void remove(h2o_iovec_t key, int flags);
};


void h2o_memcached_receiver(h2o_multithread_receiver_t *receiver, h2o_linklist_t *messages);


#endif
