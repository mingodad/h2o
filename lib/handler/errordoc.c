/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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

/* used to rewrite status code to the original code */
struct errordoc_prefilter_t : h2o_req_prefilter_t {
    h2o_headers_t req_headers;
    int status;
    const char *reason;
    h2o_headers_t res_headers;
};

/* used to capture an error response */
struct errordoc_filter_t : h2o_filter_t {
    H2O_VECTOR<h2o_errordoc_t> errordocs;
};

static void add_header(h2o_mem_pool_t *pool, h2o_headers_t *headers,
        const h2o_header_t *header)
{
    headers->push_back(pool, *header);
}

static void on_prefilter_setup_stream(h2o_req_prefilter_t *_self,
        h2o_req_t *req, h2o_ostream_t **slot)
{
    auto self = (errordoc_prefilter_t *)_self;
    h2o_headers_t headers_merged = {};
    size_t i;

    /* restore request headers (for logging) and response status */
    req->headers = self->req_headers;
    req->res.status = self->status;
    req->res.reason = self->reason;

    /* generate response headers (by merging the preserved and given) */
    for (i = 0; i != self->res_headers.size; ++i)
        add_header(&req->pool, &headers_merged, &self->res_headers[i]);
    for (i = 0; i != req->res.headers.size; ++i) {
        const auto header = req->res.headers[i];
        if (header.name == &H2O_TOKEN_CONTENT_TYPE->buf ||
            header.name == &H2O_TOKEN_CONTENT_LANGUAGE->buf ||
            header.name == &H2O_TOKEN_SET_COOKIE->buf)
            add_header(&req->pool, &headers_merged, &header);
    }
    req->res.headers = headers_merged;

    h2o_setup_next_prefilter(self, req, slot);
}

static void on_ostream_send(h2o_ostream_t *self, h2o_req_t *req,
        h2o_iovec_t *inbufs, size_t inbufcnt, int is_final)
{
    /* nothing to do */
}

static int prefilter_is_registered(h2o_req_t *req)
{
    h2o_req_prefilter_t *prefilter;
    for (prefilter = req->prefilters; prefilter != NULL; prefilter = prefilter->next)
        if (prefilter->on_setup_ostream == on_prefilter_setup_stream)
            return 1;
    return 0;
}

static void on_filter_setup_ostream(h2o_filter_t *_self, h2o_req_t *req,
        h2o_ostream_t **slot)
{
    auto self = (errordoc_filter_t *)_self;
    h2o_errordoc_t *errordoc;
    errordoc_prefilter_t *prefilter;
    h2o_iovec_t method;
    h2o_ostream_t *ostream;
    size_t i;

    if (req->res.status >= 400 && !prefilter_is_registered(req)) {
        size_t i;
        for (i = 0; i != self->errordocs.size; ++i) {
            errordoc = self->errordocs.entries + i;
            if (errordoc->status == req->res.status)
                goto Found;
        }
    }

    /* bypass to the next filter */
    req->setup_next_ostream(slot);
    return;

Found:
    /* register prefilter that rewrites the status code after the internal redirect is processed */
    prefilter = (errordoc_prefilter_t*)req->add_prefilter(sizeof(errordoc_prefilter_t));
    prefilter->on_setup_ostream = on_prefilter_setup_stream;
    prefilter->req_headers = req->headers;
    prefilter->status = req->res.status;
    prefilter->reason = req->res.reason;
    prefilter->res_headers = {};
    for (i = 0; i != req->res.headers.size; ++i) {
        const h2o_header_t *header = req->res.headers.entries + i;
        if (!(header->name == &H2O_TOKEN_CONTENT_TYPE->buf ||
                header->name == &H2O_TOKEN_CONTENT_LANGUAGE->buf))
            add_header(&req->pool, &prefilter->res_headers, header);
    }
    /* redirect internally to the error document */
    method = req->method;
    if (method.isEq("POST"))
        method.init(H2O_STRLIT("GET"));
    req->headers = {};
    req->res.headers = {};
    req->send_redirect_internal(method, errordoc->url, 0);
    /* create fake ostream that swallows the contents emitted by the generator */
    ostream = req->add_ostream(sizeof(*ostream), slot);
    ostream->do_send = on_ostream_send;
}

void h2o_errordoc_register(h2o_pathconf_t *pathconf, h2o_errordoc_t *errdocs, size_t cnt)
{
    h2o_create_new_filter_for(self, pathconf, struct errordoc_filter_t);
    size_t i;

    self->on_setup_ostream = on_filter_setup_ostream;
    self->errordocs.reserve(NULL, cnt);
    self->errordocs.size = cnt;
    for (i = 0; i != cnt; ++i) {
        const h2o_errordoc_t *src = errdocs + i;
        h2o_errordoc_t *dst = self->errordocs.entries + i;
        dst->status = src->status;
        dst->url.strdup(src->url);
    }
}
