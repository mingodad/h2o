/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Masahiro Nagano
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
#ifdef _WIN32
#else
    #include <sys/un.h>
#endif
#include "h2o.h"
#include "h2o/socketpool.h"

struct rp_handler_t : h2o_handler_t {
    h2o_url_t upstream;         /* host should be NULL-terminated */
    h2o_socketpool_t *sockpool; /* non-NULL if config.use_keepalive == 1 */
    h2o_proxy_config_vars_t config;

    rp_handler_t():upstream({}), sockpool(nullptr), config({}) {}

    void on_context_init(h2o_context_t *ctx) override;
    void on_context_dispose(h2o_context_t *ctx) override;
    void dispose(h2o_base_handler_t *self) override;
};

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    auto self = (rp_handler_t *)_self;
    auto overrides = req->pool.alloc_for<h2o_req_overrides_t>();
    const h2o_url_scheme_t *scheme;
    h2o_iovec_t *authority;

    /* setup overrides */
    *overrides = {};
    if (self->sockpool != NULL) {
        overrides->socketpool = self->sockpool;
    } else if (self->config.preserve_host) {
        overrides->hostport.host = self->upstream.host;
        overrides->hostport.port = self->upstream.get_port();
    }
    overrides->location_rewrite.match = &self->upstream;
    overrides->location_rewrite.path_prefix = req->pathconf->path;
    overrides->client_ctx = (h2o_http1client_ctx_t*)req->conn->ctx->get_handler_context(self);

    /* determine the scheme and authority */
    if (self->config.preserve_host) {
        scheme = req->scheme;
        authority = &req->authority;
    } else {
        scheme = self->upstream.scheme;
        authority = &self->upstream.authority;
    }

    /* request reprocess */
    h2o_iovec_t req_cat;
    h2o_concat(req_cat, &req->pool, self->upstream.path, h2o_iovec_t::create(req->path.base + req->pathconf->path.len,
                                                                req->path.len - req->pathconf->path.len));
    req->reprocess_request(req->method, scheme, *authority, req_cat, overrides, 0);

    return 0;
}

void rp_handler_t::on_context_init(h2o_context_t *ctx)
{
    /* use the loop of first context for handling socketpool timeouts */
    if (this->sockpool != NULL && this->sockpool->timeout == UINT64_MAX)
        h2o_socketpool_set_timeout(this->sockpool, ctx->loop, this->config.keepalive_timeout);

    /* setup a specific client context only if we need to */
    if (ctx->globalconf->proxy.io_timeout == this->config.io_timeout && !this->config.websocket.enabled)
        return;

    auto client_ctx = h2o_mem_alloc_for<h2o_http1client_ctx_t>();
    client_ctx->loop = ctx->loop;
    client_ctx->getaddr_receiver = &ctx->receivers.hostinfo_getaddr;
    if (ctx->globalconf->proxy.io_timeout == this->config.io_timeout) {
        client_ctx->io_timeout = &ctx->proxy.io_timeout;
    } else {
        client_ctx->io_timeout = h2o_mem_alloc_for<h2o_timeout_t>();
        client_ctx->io_timeout->init(client_ctx->loop, this->config.io_timeout);
    }
    if (this->config.websocket.enabled) {
        /* FIXME avoid creating h2o_timeout_t for every path-level context in case the timeout values are the same */
        client_ctx->websocket_timeout = h2o_mem_alloc_for<h2o_timeout_t>();
        client_ctx->websocket_timeout->init(client_ctx->loop, this->config.websocket.timeout);
    } else {
        client_ctx->websocket_timeout = NULL;
    }

    ctx->set_handler_context(this, client_ctx);
}

void rp_handler_t::on_context_dispose(h2o_context_t *ctx)
{
    auto client_ctx = (h2o_http1client_ctx_t*)ctx->get_handler_context(this);

    if (client_ctx == NULL)
        return;

    if (client_ctx->io_timeout != &ctx->proxy.io_timeout) {
        h2o_timeout_t::dispose(client_ctx->loop, client_ctx->io_timeout);
        h2o_mem_free(client_ctx->io_timeout);
    }
    if (client_ctx->websocket_timeout != NULL) {
        h2o_timeout_t::dispose(client_ctx->loop, client_ctx->websocket_timeout);
        h2o_mem_free(client_ctx->websocket_timeout);
    }
    h2o_mem_free(client_ctx);
}

void rp_handler_t::dispose(h2o_base_handler_t *_self)
{
    auto self = (rp_handler_t *)_self;

    h2o_mem_free(self->upstream.host.base);
    h2o_mem_free(self->upstream.path.base);
    if (self->sockpool != NULL) {
        h2o_socketpool_dispose(self->sockpool);
        h2o_mem_free(self->sockpool);
    }

    h2o_mem_free(self);
}

void h2o_proxy_register_reverse_proxy(h2o_pathconf_t *pathconf,
        h2o_url_t *upstream, h2o_proxy_config_vars_t *config)
{
    auto self = pathconf->create_handler<rp_handler_t>();
    self->on_req = on_req;
    if (config->keepalive_timeout != 0) {
        self->sockpool = h2o_mem_alloc_for<h2o_socketpool_t>();
        struct sockaddr_un sa;
        const char *to_sa_err;
        if ((to_sa_err = h2o_url_host_to_sun(upstream->host, &sa))
                == h2o_url_host_to_sun_err_is_not_unix_socket) {
            h2o_socketpool_init_by_hostport(self->sockpool, upstream->host,
                    upstream->get_port(), SIZE_MAX /* FIXME */);
        } else {
            assert(to_sa_err == NULL);
            h2o_socketpool_init_by_address(self->sockpool, (sockaddr *)&sa,
                    sizeof(sa), SIZE_MAX /* FIXME */);
        }
    }
    self->upstream.copy(NULL, upstream);
    h2o_strtolower(self->upstream.host);
    self->config = *config;
}
