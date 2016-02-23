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

#include "h2o/hello_.h"
#include <ctype.h>

static int on_req(h2o_handler_t *self, h2o_req_t *req)
{
    static h2o_generator_t generator = { NULL, NULL };
    //printf("hello_handler : %s : %d\n", req->method.base, (uint)req->method.len);
    if (! h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
        return -1;
    //printf("===Request path = %s\n", req->path.base);
    size_t body_size = 1024;
    h2o_iovec_t body;
    body.base = req->pool.alloc_for<char>(body_size);
    body.len = snprintf(body.base, body_size, "Hello %.*s\n", (int)req->path.len, req->path.base);

    req->res.content_length = body.len;
    req->res.status = 200;
    req->res.reason = "OK";
    req->addResponseHeader(H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain"));
    req->start_response(&generator);
    req->send(&body, 1, 1);

    return 0;
}

static int on_config_hello_handler(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    //auto self = (h2o_hello_configurator_t *)cmd->configurator;

    /* register */
    auto handler = ctx->pathconf->create_handler<h2o_hello_handler_t>();
    handler->on_req = on_req;

    return 0;
}

void h2o_hello_register_configurator(h2o_globalconf_t *conf)
{
    auto c = conf->configurator_create<h2o_hello_configurator_t>();
    auto cf = h2o_CONFIGURATOR_FLAG(H2O_CONFIGURATOR_FLAG_PATH |
                                    H2O_CONFIGURATOR_FLAG_DEFERRED |
                                    H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR);
    c->define_command("hello.handler", cf, on_config_hello_handler);
}
