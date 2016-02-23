/*
 * Copyright (c) 2016 Domingo Alvarez Duarte based on
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Ryosuke Matsumoto
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

#include "h2o/ctest_.h"
#include <ctype.h>

//global mutext to test congestion
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

#if 0
typedef int (*on_req_handler_ptr)(h2o_handler_t *, h2o_req_t *);

int register_handler_on_host(h2o_hostconf_t *hostconf, const char *path, on_req_handler_ptr on_req)
{
    size_t j, i;
    //printf("register_handler_on_host : %s : %s\n", hostconf->authority.host.base, path);
    //first check if it already exists
    for (j = 0; j != hostconf->paths.size; ++j) {
        auto pc = hostconf->paths[j];
        if(strcmp(path, pc.path.base) == 0)
        {
            for (i = 0; i != pc.handlers.size; ++i) {
                if(pc.handlers[i]->on_req == on_req)
                {
                    return 0; //already exists
                }
            }

        }
    }
    h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, path);
    auto handler = pathconf->create_handler<h2o_handler_t>();
    handler->on_req = on_req;
    return 1;
}

int register_handler_global(h2o_globalconf_t *globalconf, const char *path, on_req_handler_ptr on_req)
{
    size_t i;
    int result = 0;
    for (i = 0; globalconf->hosts[i] != NULL; ++i) {
        result += register_handler_on_host(globalconf->hosts[i], path, on_req);
    }
    //printf("register_handler : %s : %d\n", path, (uint)i);
    return result;
}

static int my_h2o_c_handler(h2o_handler_t *self, h2o_req_t *req)
{
    static h2o_generator_t generator = { NULL, NULL };
    printf("hello_handler : %s : %d\n", req->method.base, (uint)req->method.len);
    if (! req->method.isEq("GET"))
        return -1;
    //printf("===Request path = %s\n", req->path.base);
    size_t body_size = 1024;
    h2o_iovec_t body;
    body.base = req->pool.alloc_for<char>(body_size);
    req->res.content_length = body.len = snprintf(body.base, body_size, "Hello %.*s", (int)req->path.len, req->path.base);

    size_t cursor;
    for (cursor = 0; cursor < req->headers.size; ++cursor) {
        h2o_header_t *t = req->headers.entries + cursor;
        req->res.content_length = body.len += snprintf(
                    body.base + body.len, body_size - body.len,
                    "\n%.*s : %.*s",
                    (int)t->name->len, t->name->base,
                    (int)t->value.len, t->value.base);
    }
    req->res.status = 200;
    req->res.reason = "OK";
    req->addResponseHeader(H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain"));
    req->start_response(&generator);
    req->send(&body, 1, 1);

    return 0;
}

//register custom global handlers after reading the config file
//register_handler_global(&conf.globalconf, "/C/", my_h2o_c_handler);

#endif

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    //auto self = (h2o_ctest_handler_t *)_self;

    //intentionally one thread at a time
    pthread_mutex_lock(&mutex);
    static h2o_generator_t generator = { NULL, NULL };
    //printf("hello_handler : %s : %d\n", req->method.base, (uint)req->method.len);
    if (! h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
        return -1;
    //printf("===Request path = %s\n", req->path.base);
    const size_t max_body_size = 1024 * 1000;
    size_t body_size = 0;
    for(size_t i=0; i != req->path.len; ++i)
    {
        /*search for a number to indicate desired body size*/
        if(isdigit(req->path.base[i]))
        {
            unsigned len = 0;
            sscanf(req->path.base + i, "%u", &len);
            body_size = (len > max_body_size) ? max_body_size : len;
            break;
        }
    }
    if(!body_size) body_size = 1024;
    h2o_iovec_t body;
    body.base = req->pool.alloc_for<char>(body_size);
    body.len = snprintf(body.base, body_size, "Hello %.*s\n", (int)req->path.len, req->path.base);

    #define HDR_SEPARATOR ": "
    size_t hdr_separator_size = sizeof(HDR_SEPARATOR) - 1;
    for(size_t i=0; i != req->headers.size; ++i)
    {
        auto hdr = req->headers[i];
        size_t new_size = body.len + hdr.name->len + hdr.value.len + hdr_separator_size + 1;
        if( new_size < body_size )
        {
            memcpy(body.base + body.len, hdr.name->base, hdr.name->len);
            body.len += hdr.name->len;
            memcpy(body.base + body.len, HDR_SEPARATOR, hdr_separator_size);
            body.len += hdr_separator_size;
            memcpy(body.base + body.len, hdr.value.base, hdr.value.len);
            body.len += hdr.value.len;
            body.base[body.len++] = '\n';
        }
    }
    #undef HDR_SEPARATOR

    /*repeat the body till closest body_size*/
    while((body.len*2) < body_size)
    {
        memcpy(body.base + body.len, body.base, body.len);
        body.len *= 2;
    }

    req->res.content_length = body.len;
    req->res.status = 200;
    req->res.reason = "OK";
    req->addResponseHeader(H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain"));
    req->start_response(&generator);

    pthread_mutex_unlock(&mutex);

    req->send(&body, 1, 1);

    return 0;
}

static int on_config_ctest_handler(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    //auto self = (h2o_ctest_configurator_t *)cmd->configurator;

    /* register */
    auto handler = ctx->pathconf->create_handler<h2o_ctest_handler_t>();

    handler->on_req = on_req;

    return 0;
}

void h2o_ctest_register_configurator(h2o_globalconf_t *conf)
{
    auto c = conf->configurator_create<h2o_ctest_configurator_t>();
    auto cf = h2o_CONFIGURATOR_FLAG(H2O_CONFIGURATOR_FLAG_PATH |
                                    H2O_CONFIGURATOR_FLAG_DEFERRED |
                                    H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR);
    c->define_command("ctest.handler", cf, on_config_ctest_handler);
}
