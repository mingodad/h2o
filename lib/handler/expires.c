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
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"

struct expires_t : h2o_filter_t {
    int mode;
    h2o_iovec_t value;

    expires_t(): mode(0), value({}) {}
};

static void on_setup_ostream(h2o_filter_t *_self, h2o_req_t *req, h2o_ostream_t **slot)
{
    auto self = (expires_t *)_self;

    switch (req->res.status) {
    case 200:
    case 201:
    case 204:
    case 206:
    case 301:
    case 302:
    case 303:
    case 304:
    case 307:
        switch (self->mode) {
        case H2O_EXPIRES_MODE_ABSOLUTE:
            req->res.headers.set(&req->pool, H2O_TOKEN_EXPIRES,
                    self->value.base, self->value.len, 0);
            break;
        case H2O_EXPIRES_MODE_MAX_AGE:
            req->res.headers.add_token(&req->pool,
                    H2O_TOKEN_CACHE_CONTROL, self->value.base, self->value.len);
            break;
        default:
            assert(0);
            break;
        }
        break;
    default:
        break;
    }

    req->setup_next_ostream(slot);
}

void h2o_expires_register(h2o_pathconf_t *pathconf, h2o_expires_args_t *args)
{
    auto self = pathconf->create_filter<expires_t>();
    self->on_setup_ostream = on_setup_ostream;
    self->mode = args->mode;
    switch (args->mode) {
    case H2O_EXPIRES_MODE_ABSOLUTE:
        self->value.strdup(NULL, args->data.absolute, SIZE_MAX);
        break;
    case H2O_EXPIRES_MODE_MAX_AGE:
        self->value.base = h2o_mem_alloc_for<char>(128);
        self->value.len = sprintf(self->value.base, "max-age=%" PRIu64, args->data.max_age);
        break;
    default:
        assert(0);
        break;
    }
}
