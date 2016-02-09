/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Daisuke Maki
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
#include "h2o.h"

static void on_send(h2o_ostream_t *self, h2o_req_t *req, h2o_iovec_t *inbufs,
        size_t inbufcnt, int is_final)
{
    /* nothing to do */
}

static void on_setup_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    h2o_iovec_t dest, method;
    ssize_t xru_index;

    /* obtain x-reproxy-url header, or skip to next ostream */
    if ((xru_index = req->res.headers.find(H2O_TOKEN_X_REPROXY_URL, -1)) == -1) {
        req->setup_next_ostream(slot);
        return;
    }
    dest = req->res.headers[xru_index].value;
    req->res.headers.remove(xru_index);

    /* setup params */
    switch (req->res.status) {
    case 307:
    case 308:
        method = req->method;
        break;
    default:
        method.init(H2O_STRLIT("GET"));
        req->entity = {};
        break;
    }

    /* request internal redirect (is deferred) */
    req->send_redirect_internal(method, dest, 0);

    /* setup filter (that swallows the response until the timeout gets fired) */
    h2o_ostream_t *ostream = req->add_ostream(sizeof(*ostream), slot);
    ostream->do_send = on_send;
}

void h2o_reproxy_register(h2o_pathconf_t *pathconf)
{
    h2o_create_new_filter_for(self, pathconf, h2o_filter_t);
    self->on_setup_ostream = on_setup_ostream;
}
