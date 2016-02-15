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
#include <stddef.h>
#include <stdlib.h>
#include <sys/time.h>
#include "h2o.h"
#include "h2o/memcached.h"

void h2o_context_t::init_pathconf_context(h2o_pathconf_t *pathconf)
{
    /* add pathconf to the inited list (or return if already inited) */
    size_t i;
    for (i = 0; i != this->_pathconfs_inited.size; ++i)
        if (this->_pathconfs_inited[i] == pathconf)
            return;
    this->_pathconfs_inited.push_back(NULL, pathconf);

#define DOIT(list) \
    do { \
        size_t i; \
        for (i = 0; i != pathconf->list.size; ++i) { \
            auto o = pathconf->list[i];  \
            if (o->on_context_init != NULL)  \
                o->on_context_init(o, this); \
        } \
    } while (0)

    DOIT(handlers);
    DOIT(filters);
    DOIT(loggers);

#undef DOIT
}

void h2o_context_t::dispose_pathconf_context(h2o_pathconf_t *pathconf)
{
    /* nullify pathconf in the inited list (or return if already disposed) */
    size_t i;
    for (i = 0; i != this->_pathconfs_inited.size; ++i)
        if (this->_pathconfs_inited[i] == pathconf)
            break;
    if (i == this->_pathconfs_inited.size)
        return;
    this->_pathconfs_inited[i] = NULL;

#define DOIT(list) \
    do {                 \
        size_t i;        \
        for (i = 0; i != pathconf->list.size; ++i) { \
            auto o = pathconf->list[i];     \
            if (o->on_context_dispose != NULL)       \
                o->on_context_dispose(o, this);       \
        }                \
    } while (0)

    DOIT(handlers);
    DOIT(filters);
    DOIT(loggers);

#undef DOIT
}

//void h2o_context_t::init(h2o_context_t *ctx, h2o_loop_t *loop, h2o_globalconf_t *config)
//h2o_context_t::h2o_context_t(h2o_loop_t *loop, h2o_globalconf_t *config)
void h2o_context_t::init(h2o_loop_t *loop, h2o_globalconf_t *config)
{
    size_t i, j;

    assert( (this->loop == nullptr) && (this->globalconf == nullptr));
    assert(config->hosts[0] != NULL);

    //h2o_clearmem(this);
    this->shutdown_requested = 0;
    this->_timestamp_cache = {};
    this->_pathconfs_inited = {};
    this->http1 = {};
    this->http2 = {};
    this->proxy = {};

    this->loop = loop;
    this->globalconf = config;
    this->zero_timeout.init(this->loop, 0);
    this->one_sec_timeout.init(this->loop, 1000);
    this->queue = h2o_multithread_create_queue(loop);
    h2o_multithread_register_receiver(this->queue, &this->receivers.hostinfo_getaddr, h2o_hostinfo_getaddr_receiver);
    this->filecache = h2o_filecache_t::create(config->filecache.capacity);

    this->handshake_timeout.init(this->loop, config->handshake_timeout);
    this->http1.req_timeout.init(this->loop, config->http1.req_timeout);
    this->http2.idle_timeout.init(this->loop, config->http2.idle_timeout);
    this->http2._conns.init_anchor();
    this->proxy.client_ctx.loop = loop;
    this->proxy.io_timeout.init(this->loop, config->proxy.io_timeout);
    this->proxy.client_ctx.getaddr_receiver = &this->receivers.hostinfo_getaddr;
    this->proxy.client_ctx.io_timeout = &this->proxy.io_timeout;

    this->_module_configs = h2o_mem_calloc_for<void *>(config->_num_config_slots);

    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&mutex);
    for (i = 0; config->hosts[i] != NULL; ++i) {
        auto hostconf = config->hosts[i];
        for (j = 0; j != hostconf->paths.size; ++j) {
            auto pathconf = hostconf->paths.entries + j;
            this->init_pathconf_context(pathconf);
        }
        this->init_pathconf_context(&hostconf->fallback_path);
    }
    pthread_mutex_unlock(&mutex);
}

//void h2o_context_t::dispose(h2o_context_t *ctx)
h2o_context_t::~h2o_context_t()
{
    if(this->loop && this->globalconf)
    {
        auto config = this->globalconf;
        size_t i, j;

        for (i = 0; config->hosts[i] != NULL; ++i) {
            auto hostconf = config->hosts[i];
            for (j = 0; j != hostconf->paths.size; ++j) {
                auto pathconf = hostconf->paths[j];
                this->dispose_pathconf_context(&pathconf);
            }
            this->dispose_pathconf_context(&hostconf->fallback_path);
        }
		this->_pathconfs_inited.clear_free();
        h2o_mem_free(this->_module_configs);
        h2o_timeout_t::dispose(this->loop, &this->zero_timeout);
        h2o_timeout_t::dispose(this->loop, &this->one_sec_timeout);
        h2o_timeout_t::dispose(this->loop, &this->handshake_timeout);
        h2o_timeout_t::dispose(this->loop, &this->http1.req_timeout);
        h2o_timeout_t::dispose(this->loop, &this->http2.idle_timeout);
        h2o_timeout_t::dispose(this->loop, &this->proxy.io_timeout);
        /* what should we do here? assert(!h2o_linklist_is_empty(&this->http2._conns); */

        h2o_filecache_t::destroy(this->filecache);
        this->filecache = NULL;

        /* TODO assert that the all the getaddrinfo threads are idle */
        h2o_multithread_unregister_receiver(this->queue, &this->receivers.hostinfo_getaddr);
        h2o_multithread_destroy_queue(this->queue);

    #if H2O_USE_LIBUV
        /* make sure the handles released by h2o_timeout_t::dispose get freed */
        uv_run(this->loop, UV_RUN_NOWAIT);
    #endif
        this->loop = nullptr;
        this->globalconf = nullptr;
    }
}

void h2o_context_t::request_shutdown()
{
    this->shutdown_requested = 1;
	auto cb1 = this->globalconf->http1.callbacks.request_shutdown;
    if (cb1 != NULL) cb1(this);
	auto cb2 = this->globalconf->http2.callbacks.request_shutdown;
    if (cb2 != NULL) cb2(this);
}

void h2o_context_t::update_timestamp_cache()
{
	auto &tm_cache = this->_timestamp_cache;
    time_t prev_sec = tm_cache.tv_at.tv_sec;
    tm_cache.uv_now_at = h2o_now(this->loop);
    gettimeofday(&tm_cache.tv_at, NULL);
    if (tm_cache.tv_at.tv_sec != prev_sec) {
        struct tm gmt;
        /* update the string cache */
        if (tm_cache.value != NULL)
            h2o_mem_release_shared(tm_cache.value);
        tm_cache.value = h2o_mem_alloc_shared_for<h2o_timestamp_string_t>(1, NULL);
        gmtime_r(&tm_cache.tv_at.tv_sec, &gmt);
        h2o_time2str_rfc1123(tm_cache.value->rfc1123, &gmt);
        h2o_time2str_log(tm_cache.value->log, tm_cache.tv_at.tv_sec);
    }
}
