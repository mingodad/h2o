/*
 * Copyright (c) 2015 DeNA Co., Ltd.
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
#include <stdlib.h>
#include "../../test.h"
#include "../../../../lib/handler/redirect.c"

static h2o_context_t *ctx;

static int check_header(h2o_res_t *res, const h2o_token_t *header_name, const char *expected)
{
    size_t index = res->headers.find( header_name, SIZE_MAX);
    if (index == SIZE_MAX)
        return 0;
    return h2o_lcstris(res->headers[index].value.base, res->headers[index].value.len, expected, strlen(expected));
}

void test_lib__handler__redirect_c()
{
    h2o_globalconf_t globalconf; //should be declared before h2o_context_t
    h2o_context_t test_ctx;
    h2o_hostconf_t *hostconf;
    h2o_pathconf_t *pathconf;

    hostconf = globalconf.register_host(h2o_iovec_t::create(H2O_STRLIT("default")), 65535);
    pathconf = hostconf->register_path("/", 0);
    h2o_redirect_register(pathconf, 0, 301, "https://example.com/bar/");

    test_ctx.init(test_loop, &globalconf);
    ctx = &test_ctx;

    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(ctx, ctx->globalconf->hosts);
        conn->req.input.method = h2o_iovec_t::create(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_t::create(H2O_STRLIT("/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, H2O_TOKEN_LOCATION, "https://example.com/bar/"));
        ok(conn->body->size != 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(ctx, ctx->globalconf->hosts);
        conn->req.input.method = h2o_iovec_t::create(H2O_STRLIT("GET"));
        conn->req.input.path = h2o_iovec_t::create(H2O_STRLIT("/abc"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, H2O_TOKEN_LOCATION, "https://example.com/bar/abc"));
        ok(conn->body->size != 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(ctx, ctx->globalconf->hosts);
        conn->req.input.method = h2o_iovec_t::create(H2O_STRLIT("HEAD"));
        conn->req.input.path = h2o_iovec_t::create(H2O_STRLIT("/"));
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, H2O_TOKEN_LOCATION, "https://example.com/bar/"));
        ok(conn->body->size == 0);
        h2o_loopback_destroy(conn);
    }
}
