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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"

struct chunked_encoder_t : h2o_ostream_t {
    char buf[64];
};

static void send_chunk(h2o_ostream_t *_self, h2o_req_t *req,
        h2o_iovec_t *inbufs, size_t inbufcnt, int is_final)
{
    auto self = (chunked_encoder_t *)_self;
    auto outbufs = (h2o_iovec_t *)h2o_mem_alloca(sizeof(h2o_iovec_t) * (inbufcnt + 2));
    size_t chunk_size, i;
    h2o_iovec_t *ob = outbufs;

    /* calc chunk size */
    chunk_size = 0;
    for (i = 0; i != inbufcnt; ++i)
        chunk_size += inbufs[i].len;

    /* create chunk header and output data */
    if (chunk_size != 0) {
        ob->base = self->buf;
        ob->len = sprintf(self->buf, "%zx\r\n", chunk_size);
        assert(ob->len < sizeof(self->buf));
        ob++;
        memcpy(ob, inbufs, sizeof(h2o_iovec_t) * inbufcnt);
        ob += inbufcnt;
        ob->base = (char*)"\r\n0\r\n\r\n";
        ob->len = is_final ? 7 : 2;
        ob++;
    } else if (is_final) {
        ob->base = (char*)"0\r\n\r\n";
        ob->len = 5;
        ob++;
    }

    req->send_next(self, outbufs, /*bufcount*/(ob-outbufs), is_final);
    h2o_mem_alloca_free(outbufs);
}

static void on_setup_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    /* do nothing if not HTTP/1.1 or content-length is known */
    if (req->res.content_length != SIZE_MAX || req->version != 0x101)
        goto Next;
    /* RFC 2616 4.4 states that the following status codes (and response to a HEAD method) should not include message body */
    if ((100 <= req->res.status && req->res.status <= 199) || req->res.status == 204 || req->res.status == 304)
        goto Next;
    else if (req->input.method.isEq("HEAD"))
        goto Next;
    /* we cannot handle certain responses (like 101 switching protocols) */
    if (req->res.status != 200) {
        req->http1_is_persistent = 0;
        goto Next;
    }
    /* skip if content-encoding header is being set */
    if (req->res.headers.find(H2O_TOKEN_TRANSFER_ENCODING, -1) != -1)
        goto Next;

    /* set content-encoding header */
    req->addResponseHeader(H2O_TOKEN_TRANSFER_ENCODING, H2O_STRLIT("chunked"));

    /* setup filter */
    {
        auto encoder = (chunked_encoder_t *)req->add_ostream(sizeof(chunked_encoder_t), slot);
        encoder->do_send = send_chunk;
        slot = &encoder->next;
    }

Next:
    req->setup_next_ostream(slot);
}

void h2o_chunked_register(h2o_pathconf_t *pathconf)
{
    auto self = pathconf->create_filter<h2o_filter_t>();
    self->on_setup_ostream = on_setup_ostream;
}
