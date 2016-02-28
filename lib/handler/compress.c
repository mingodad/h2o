/*
 * Copyright (c) 2015,2016 Justin Zhu, DeNA Co., Ltd., Kazuho Oku
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
#include <stdlib.h>
#include "h2o.h"

#ifndef BUF_SIZE
#define BUF_SIZE 8192
#endif

struct compress_filter_t : h2o_filter_t{
    h2o_compress_args_t args;
};

struct compress_encoder_t : h2o_ostream_t {
    h2o_compress_context_t *compressor;
};

static void do_send(h2o_ostream_t *_self, h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, int is_final)
{
    auto self = (compress_encoder_t *)_self;
    h2o_iovec_t *outbufs;
    size_t outbufcnt;

    self->compressor->compress(self->compressor, inbufs, inbufcnt, is_final, &outbufs, &outbufcnt);

    /* send next */
    req->send_next(self, outbufs, outbufcnt, is_final);
}

static void on_setup_ostream(h2o_filter_t *_self, h2o_req_t *req, h2o_ostream_t **slot)
{
    auto self = (compress_filter_t *)_self;
    compress_encoder_t *encoder;
    int compressible_types;
    h2o_compress_context_t *compressor;
    ssize_t i;
    size_t content_encoding_header_index, accept_ranges_header_index;

    if (req->version < 0x101)
        goto Next;
    if (req->res.status != 200)
        goto Next;
    if (h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("HEAD")))
        goto Next;
    if (req->res.mime_attr == NULL)
        req->fill_mime_attributes();
    if (!req->res.mime_attr->is_compressible)
        goto Next;
    /* 100 is a rough estimate */
    if (req->res.content_length <= 100)
        goto Next;
    /* skip if no accept-encoding is set */
    if ((i = req->headers.find(H2O_TOKEN_ACCEPT_ENCODING, -1)) == -1)
        goto Next;
    if (!h2o_contains_token(req->headers.entries[i].value.base, req->headers.entries[i].value.len, H2O_STRLIT("gzip"), ','))
        goto Next;
    /* skip if failed to gather the list of compressible types */
    if ((compressible_types = h2o_get_compressible_types(&req->headers)) == 0)
        goto Next;

    content_encoding_header_index = SIZE_MAX, accept_ranges_header_index = SIZE_MAX;
    /* skip if content-encoding header is being set (as well as obtain the location of accept-ranges */
    for (size_t idx = 0; idx != req->res.headers.size; ++idx) {
        if (req->res.headers.entries[idx].name == &H2O_TOKEN_CONTENT_ENCODING->buf)
            content_encoding_header_index = idx;
        else if (req->res.headers.entries[idx].name == &H2O_TOKEN_ACCEPT_RANGES->buf)
            accept_ranges_header_index = idx;
        else
            continue;
    }
    if (content_encoding_header_index != SIZE_MAX)
        goto Next;

    /* open the compressor */
#if H2O_USE_BROTLI
    if (self->args.brotli.quality != -1 && (compressible_types & H2O_COMPRESSIBLE_BROTLI) != 0) {
        compressor = h2o_compress_brotli_open(&req->pool, self->args.brotli.quality, req->res.content_length);
    } else
#endif
    if (self->args.gzip.quality != -1 && (compressible_types & H2O_COMPRESSIBLE_GZIP) != 0) {
        compressor = h2o_compress_gzip_open(&req->pool, self->args.gzip.quality);
    } else {
        goto Next;
    }

    /* adjust the response headers */
    req->res.content_length = SIZE_MAX;
    req->addResponseHeader(H2O_TOKEN_CONTENT_ENCODING, compressor->name);
    req->addResponseHeader(H2O_TOKEN_VARY, H2O_STRLIT("accept-encoding"));
    if (accept_ranges_header_index != SIZE_MAX) {
        req->res.headers[accept_ranges_header_index].value = h2o_iovec_t::create(H2O_STRLIT("none"));
    } else {
        req->addResponseHeader(H2O_TOKEN_ACCEPT_RANGES, H2O_STRLIT("none"));
    }

    /* setup filter */
    encoder = (compress_encoder_t *)req->add_ostream(sizeof(*encoder), slot);
    encoder->do_send = do_send;
    slot = &encoder->next;
    encoder->compressor = compressor;

    /* adjust preferred chunk size (compress by 8192 bytes) */
    if (req->preferred_chunk_size > BUF_SIZE)
        req->preferred_chunk_size = BUF_SIZE;

Next:
    req->setup_next_ostream(slot);
}

void h2o_compress_register(h2o_pathconf_t *pathconf, h2o_compress_args_t *args)
{
    auto self = pathconf->create_filter<compress_filter_t>();
    self->on_setup_ostream = on_setup_ostream;
    self->args = *args;
}
