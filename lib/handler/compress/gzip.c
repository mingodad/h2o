/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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
#include <zlib.h>
#include "h2o.h"

#define WINDOW_BITS 31
#ifndef BUF_SIZE /* is altered by unit test */
#define BUF_SIZE 8192
#endif

typedef H2O_VECTOR<h2o_iovec_t> iovec_vector_t;

struct gzip_context_t : h2o_compress_context_t {
    z_stream zs;
    int zs_is_open;
    iovec_vector_t bufs;
    h2o_mem_pool_t *pool;
};

static void *alloc_cb(void *_self, unsigned int cnt, unsigned int sz)
{
    auto self = (gzip_context_t *)_self;
    return self->pool->alloc_for<char>(cnt * (size_t)sz);
}

static void free_cb(void *_self, void *ptr)
{
    //does nothing we allocate everithing from pool
    //we still need it because if not zlib will call free() directly
}

static void expand_buf(h2o_mem_pool_t *pool, iovec_vector_t *bufs)
{
    auto buf = bufs->append_new(pool);
    buf->base = pool->alloc_for<char>(BUF_SIZE);
    buf->len = 0;
}

static size_t compress_chunk(gzip_context_t *self, const void *src, size_t len, int flush, size_t bufindex)
{
    int ret;

    self->zs.next_in = (Bytef *)src;
    self->zs.avail_in = (unsigned)len;

    /* man says: If deflate returns with avail_out == 0, this function must be called again with the same value of the flush
     * parameter and more output space (updated avail_out), until the flush is complete (deflate returns with non-zero avail_out).
     */
    do {
        /* expand buffer (note: in case of Z_SYNC_FLUSH we need to supply at least 6 bytes of output buffer) */
        if (self->bufs[bufindex].len + 32 > BUF_SIZE) {
            ++bufindex;
            if (bufindex == self->bufs.size)
                expand_buf(self->pool, &self->bufs);
            self->bufs[bufindex].len = 0;
        }
        self->zs.next_out = (Bytef *)self->bufs[bufindex].base + self->bufs[bufindex].len;
        self->zs.avail_out = (unsigned)(BUF_SIZE - self->bufs[bufindex].len);
        ret = deflate(&self->zs, flush);
        assert(ret == Z_OK || ret == Z_STREAM_END);
        self->bufs[bufindex].len = BUF_SIZE - self->zs.avail_out;
    } while (self->zs.avail_out == 0 && ret != Z_STREAM_END);

    return bufindex;
}

static void do_compress(h2o_compress_context_t *_self, h2o_iovec_t *inbufs, size_t inbufcnt, int is_final, h2o_iovec_t **outbufs,
                        size_t *outbufcnt)
{
    auto self = (gzip_context_t *)_self;
    size_t outbufindex;
    h2o_iovec_t last_buf;

    outbufindex = 0;
    self->bufs.entries[0].len = 0;

    if (inbufcnt != 0) {
        size_t i;
        for (i = 0; i != inbufcnt - 1; ++i)
            outbufindex = compress_chunk(self, inbufs[i].base, inbufs[i].len, Z_NO_FLUSH, outbufindex);
        last_buf = inbufs[i];
    } else {
        last_buf = {};
    }
    outbufindex = compress_chunk(self, last_buf.base, last_buf.len, is_final ? Z_FINISH : Z_SYNC_FLUSH, outbufindex);

    *outbufs = self->bufs.entries;
    *outbufcnt = outbufindex + 1;

    if (is_final) {
        deflateEnd(&self->zs);
        self->zs_is_open = 0;
    }
}

static void do_free(void *_self)
{
    auto self = (gzip_context_t*)_self;

    if (self->zs_is_open)
        deflateEnd(&self->zs);
}

h2o_compress_context_t *h2o_compress_gzip_open(h2o_mem_pool_t *pool, int quality)
{
    auto self = pool->alloc_shared_for<gzip_context_t>(1, do_free);

    self->name = h2o_iovec_t::create(H2O_STRLIT("gzip"));
    self->compress = do_compress;
    self->pool = pool;
    self->zs.zalloc = alloc_cb;
    self->zs.zfree = free_cb;
    self->zs.opaque = self;
    /* Z_BEST_SPEED for on-the-fly compression, memlevel set to 8 as suggested by the manual */
    deflateInit2(&self->zs, quality, Z_DEFLATED, WINDOW_BITS, 8, Z_DEFAULT_STRATEGY);
    self->zs_is_open = 1;
    self->bufs = (iovec_vector_t){};
    expand_buf(pool, &self->bufs);

    return self;
}
