/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd.
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
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "h2o.h"
#include "h2o/configurator.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
#ifdef _WIN32
    #include "win32_port.h"
#endif // _WIN32

static h2o_hostconf_t *create_hostconf(h2o_globalconf_t *globalconf)
{
    auto hostconf = h2o_mem_alloc_for<h2o_hostconf_t>();
    *hostconf = (h2o_hostconf_t){globalconf};
    h2o_pathconf_t::init(&hostconf->fallback_path, globalconf, NULL, globalconf->mimemap);
    hostconf->mimemap = globalconf->mimemap;
    h2o_mem_addref_shared(hostconf->mimemap);
    return hostconf;
}

static void destroy_hostconf(h2o_hostconf_t *hostconf)
{
    size_t i;
    if (hostconf->authority.hostport.base != hostconf->authority.host.base)
        h2o_mem_free(hostconf->authority.hostport.base);
    h2o_mem_free(hostconf->authority.host.base);
    for (i = 0; i != hostconf->paths.size; ++i) {
        auto pathconf = hostconf->paths[i];
        h2o_pathconf_t::dispose(&pathconf);
    }
    h2o_mem_free(hostconf->paths.entries);
    h2o_pathconf_t::dispose(&hostconf->fallback_path);
    h2o_mem_release_shared(hostconf->mimemap);

    h2o_mem_free(hostconf);
}

void h2o_pathconf_t::init(h2o_pathconf_t *pathconf, h2o_globalconf_t *globalconf, const char *path, h2o_mimemap_t *mimemap)
{
    h2o_clearmem(pathconf);
    pathconf->global = globalconf;
    h2o_chunked_register(pathconf);
    if (path != NULL)
        pathconf->path = h2o_strdup(NULL, path, SIZE_MAX);
    h2o_mem_addref_shared(mimemap);
    pathconf->mimemap = mimemap;
}

void h2o_pathconf_t::dispose(h2o_pathconf_t *pathconf)
{
#define DESTROY_LIST(list) \
    do { \
        size_t i; \
        for (i = 0; i != pathconf->list.size; ++i) {  \
            auto e = pathconf->list[i]; \
            e->dispose(e); \
            delete e; \
        } \
        pathconf->list.clear_free(); \
    } while (0)
    DESTROY_LIST(handlers);
    DESTROY_LIST(filters);
    DESTROY_LIST(loggers);
#undef DESTROY_LIST

    h2o_mem_free(pathconf->path.base);
    if (pathconf->mimemap != NULL)
        h2o_mem_release_shared(pathconf->mimemap);
}

//void h2o_globalconf_t::init()
h2o_globalconf_t::h2o_globalconf_t()
{
	//h2o_clearmem(this);
    this->hosts = h2o_mem_alloc_for<h2o_hostconf_t*>();
    this->hosts[0] = NULL;
    this->configurators = {};
    this->configurators.init_anchor();
    this->server_name = {};
    this->server_name.init(H2O_STRLIT("h2o-cpp/" H2O_VERSION));
    this->max_request_entity_size = H2O_DEFAULT_MAX_REQUEST_ENTITY_SIZE;
    this->max_delegations = H2O_DEFAULT_MAX_DELEGATIONS;
    this->user = nullptr;
    this->handshake_timeout = H2O_DEFAULT_HANDSHAKE_TIMEOUT;
    this->http1 = {};
    this->http1.req_timeout = H2O_DEFAULT_HTTP1_REQ_TIMEOUT;
    this->http1.upgrade_to_http2 = H2O_DEFAULT_HTTP1_UPGRADE_TO_HTTP2;
    this->http1.callbacks = H2O_HTTP1_CALLBACKS;
    this->http2 = {};
    this->http2.idle_timeout = H2O_DEFAULT_HTTP2_IDLE_TIMEOUT;
    this->http2.max_concurrent_requests_per_connection = H2O_HTTP2_SETTINGS_HOST.max_concurrent_streams;
    this->http2.max_streams_for_priority = 16;
    this->http2.callbacks = H2O_HTTP2_CALLBACKS;
    this->proxy.io_timeout = H2O_DEFAULT_PROXY_IO_TIMEOUT;
    this->mimemap = h2o_mimemap_create();
    this->filecache = {};
    this->_num_config_slots = 0;

    this->configurator_init_core();
}

h2o_pathconf_t *h2o_config_register_path(h2o_hostconf_t *hostconf, const char *pathname)
{
    auto pathconf = hostconf->paths.append_new(NULL);

    h2o_pathconf_t::init(pathconf, hostconf->global, pathname, hostconf->mimemap);

    return pathconf;
}

h2o_hostconf_t *h2o_config_register_host(h2o_globalconf_t *config, h2o_iovec_t host, uint16_t port)
{
    h2o_hostconf_t *hostconf = NULL;
    h2o_iovec_t host_lc;

    assert(host.len != 0);

    /* convert hostname to lowercase */
    host_lc.strdup(host);
    h2o_strtolower(host_lc);

    { /* return NULL if given authority is already registered */
        h2o_hostconf_t **p;
        for (p = config->hosts; *p != NULL; ++p)
            if ((*p)->authority.host.isEq(host_lc) &&
                (*p)->authority.port == port)
                goto Exit;
    }

    /* create hostconf */
    hostconf = create_hostconf(config);
    hostconf->authority.host = host_lc;
    hostconf->authority.port = port;
    if (hostconf->authority.port == H2O_PORT_NOT_SET) {
        hostconf->authority.hostport = hostconf->authority.host;
    } else {
        size_t hostport_size = hostconf->authority.host.len + sizeof("[]:" H2O_UINT16_LONGEST_STR);
        hostconf->authority.hostport.base = h2o_mem_alloc_for<char>(hostport_size);
        const char *hostport_fmt = (strchr(hostconf->authority.host.base, ':') != NULL)
                                    ? "[%s]:%" PRIu16 : "%s:%" PRIu16;
        hostconf->authority.hostport.len =
                snprintf(hostconf->authority.hostport.base, hostport_size,
                        hostport_fmt, hostconf->authority.host.base, port);
    }

    /* append to the list */
    h2o_append_to_null_terminated_list((void ***)&config->hosts, hostconf);

Exit:
    if(!hostconf) {
        h2o_mem_free(host_lc.base);
    }
    return hostconf;
}

//void h2o_globalconf_t::dispose()
h2o_globalconf_t::~h2o_globalconf_t()
{
    size_t i;

    for (i = 0; this->hosts[i] != NULL; ++i) {
        auto hostconf = this->hosts[i];
        destroy_hostconf(hostconf);
    }
    h2o_mem_free(this->hosts);

    h2o_mem_release_shared(this->mimemap);
    this->dispose_configurators();
}
