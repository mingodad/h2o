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
#include "../../test.h"
#include "../../../../lib/core/headers.c"

static void test_add_header_token(void)
{
    h2o_mem_pool_t pool;
    h2o_headers_t headers = {};

    pool.init();

    headers.add_token(&pool, H2O_TOKEN_VARY, H2O_STRLIT("Cookie"));
    ok(headers.size == 1);
    ok(headers[0].name == &H2O_TOKEN_VARY->buf);
    ok(h2o_memis(headers[0].value.base, headers[0].value.len, H2O_STRLIT("Cookie")));
    headers.add_token(&pool, H2O_TOKEN_VARY, H2O_STRLIT("Accept-Encoding"));
    ok(headers.size == 1);
    ok(headers[0].name == &H2O_TOKEN_VARY->buf);
    ok(h2o_memis(headers[0].value.base, headers[0].value.len, H2O_STRLIT("Cookie, Accept-Encoding")));

    pool.clear();
}

void test_lib__core__headers_c(void)
{
    subtest("add_header_token", test_add_header_token);
}
