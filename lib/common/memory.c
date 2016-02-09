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
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "h2o/memory.h"

void *(*h2o_mem__set_secure)(void *, int, size_t) = memset;

static __thread h2o_mem_recycle_t mempool_allocator = {16};

void h2o_fatal(const char *msg)
{
    fprintf(stderr, "fatal:%s\n", msg);
    abort();
}

void *h2o_mem_recycle_t::alloc(size_t sz)
{
    if (this->cnt == 0)
        return h2o_mem_alloc(sz);
    /* detach and return the pooled pointer */
    auto chunk = this->_link;
    assert(chunk != NULL);
    this->_link = chunk->next;
    --this->cnt;
    return chunk;
}

void h2o_mem_recycle_t::free(void *p)
{
    if (this->cnt == this->max) {
        h2o_mem_free(p);
        return;
    }
    /* register the pointer to the pool */
    auto chunk = (h2o_mem_recycle_chunk_t*)p;
    chunk->next = this->_link;
    this->_link = chunk;
    ++this->cnt;
}

void h2o_mem_pool_t::init()
{
    this->chunks = NULL;
    this->chunk_offset = sizeof(this->chunks->bytes);
    this->directs = NULL;
    this->shared_refs = NULL;
}

void h2o_mem_pool_t::clear()
{
    /* release the refcounted chunks */
    if (this->shared_refs != NULL) {
        h2o_mem_pool_shared_ref_t *ref = this->shared_refs;
        do {
            h2o_mem_release_shared(ref->entry->bytes);
        } while ((ref = ref->next) != NULL);
        this->shared_refs = NULL;
    }
    /* release the direct chunks */
    if (this->directs != NULL) {
        h2o_mem_pool_direct_t *direct = this->directs, *next;
        do {
            next = direct->next;
            h2o_mem_free(direct);
        } while ((direct = next) != NULL);
        this->directs = NULL;
    }
    /* free chunks, and reset the first chunk */
    while (this->chunks != NULL) {
        h2o_mem_pool_chunk_t *next = this->chunks->next;
        mempool_allocator.free(this->chunks);
        this->chunks = next;
    }
    this->chunk_offset = sizeof(this->chunks->bytes);
}

void *h2o_mem_pool_t::alloc(size_t sz)
{
    void *ret;

    if (sz >= sizeof(this->chunks->bytes) / 4) {
        /* allocate large requests directly */
        auto newp = (h2o_mem_pool_direct_t *)h2o_mem_alloc(offsetof(struct h2o_mem_pool_direct_t, bytes) + sz);
        newp->next = (h2o_mem_pool_direct_t*)directs;
        this->directs = newp;
        return newp->bytes;
    }

    /* 16-bytes rounding */
    sz = (sz + 15) & ~15;
    if (sizeof(this->chunks->bytes) - this->chunk_offset < sz) {
        /* allocate new chunk */
        auto newp = mempool_allocator.alloc_for<h2o_mem_pool_chunk_t>();
        newp->next = this->chunks;
        this->chunks = newp;
        this->chunk_offset = 0;
    }

    ret = this->chunks->bytes + this->chunk_offset;
    this->chunk_offset += sz;
    return ret;
}

static void link_shared(h2o_mem_pool_t *pool, h2o_mem_pool_shared_entry_t *entry)
{
    auto ref = pool->alloc_for<h2o_mem_pool_shared_ref_t>();
    ref->entry = entry;
    ref->next = pool->shared_refs;
    pool->shared_refs = ref;
}

void *h2o_mem_pool_t::alloc_shared(size_t sz, mem_pool_dispose_cb_t dispose)
{
    void *p = h2o_mem_alloc_shared(sz, dispose);
    auto entry = H2O_STRUCT_FROM_MEMBER(h2o_mem_pool_shared_entry_t, bytes, p);
    ::link_shared(this, entry);
    return entry->bytes;
}

void h2o_mem_pool_t::link_shared(void *p)
{
    h2o_mem_addref_shared(p);
    ::link_shared(this, H2O_STRUCT_FROM_MEMBER(h2o_mem_pool_shared_entry_t, bytes, p));
}

static size_t topagesize(size_t capacity)
{
    size_t pagesize = getpagesize();
    return (offsetof(h2o_buffer_t, _buf) + capacity + pagesize - 1) / pagesize * pagesize;
}

void h2o_buffer_t::free(h2o_buffer_t *buffer)
{
#if 0
    /* caller should assert that the buffer is not part of the prototype */
    if (buffer->capacity == buffer->_prototype->_initial_buf.capacity) {
        buffer->_prototype->allocator.free(buffer);
    } else if (buffer->_fd != -1) {
        close(buffer->_fd);
        munmap((void *)buffer, topagesize(buffer->capacity));
    } else {
        h2o_mem_free(buffer);
    }
#endif
}

h2o_iovec_t h2o_buffer_t::reserve(size_t min_guarantee)
{
#if 0
    h2o_buffer_t *inbuf = *_inbuf;
    h2o_iovec_t ret;

    if (inbuf->bytes == NULL) {
        h2o_buffer_prototype_t *prototype = H2O_STRUCT_FROM_MEMBER(h2o_buffer_prototype_t, _initial_buf, inbuf);
        if (min_guarantee <= prototype->_initial_buf.capacity) {
            min_guarantee = prototype->_initial_buf.capacity;
            inbuf = (h2o_buffer_t *)prototype->allocator.alloc(offsetof(h2o_buffer_t, _buf) + min_guarantee);
        } else {
            inbuf = (h2o_buffer_t *)h2o_mem_alloc(offsetof(h2o_buffer_t, _buf) + min_guarantee);
        }
        *_inbuf = inbuf;
        inbuf->size = 0;
        inbuf->bytes = inbuf->_buf;
        inbuf->capacity = min_guarantee;
        inbuf->_prototype = prototype;
        inbuf->_fd = -1;
    } else {
        if (min_guarantee <= inbuf->capacity - inbuf->size - (inbuf->bytes - inbuf->_buf)) {
            /* ok */
        } else if ((inbuf->size + min_guarantee) * 2 <= inbuf->capacity) {
            /* the capacity should be less than or equal to 2 times of: size + guarantee */
            memmove(inbuf->_buf, inbuf->bytes, inbuf->size);
            inbuf->bytes = inbuf->_buf;
        } else {
            size_t new_capacity = inbuf->capacity;
            do {
                new_capacity *= 2;
            } while (new_capacity - inbuf->size < min_guarantee);
            if (inbuf->_prototype->mmap_settings != NULL && inbuf->_prototype->mmap_settings->threshold <= new_capacity) {
                size_t new_allocsize = topagesize(new_capacity);
                int fd;
                h2o_buffer_t *newp;
                if (inbuf->_fd == -1) {
                    char *tmpfn = (char *)h2o_mem_alloca(strlen(inbuf->_prototype->mmap_settings->fn_template) + 1);
                    strcpy(tmpfn, inbuf->_prototype->mmap_settings->fn_template);
                    if ((fd = mkstemp(tmpfn)) == -1) {
                        fprintf(stderr, "failed to create temporary file:%s:%s\n", tmpfn, strerror(errno));
                        goto MapError;
                    }
                    unlink(tmpfn);
                    h2o_mem_alloca_free(tmpfn);
                } else {
                    fd = inbuf->_fd;
                }
                if (ftruncate(fd, new_allocsize) != 0) {
                    perror("failed to resize temporary file");
                    goto MapError;
                }
                if ((newp = (h2o_buffer_t *)mmap(NULL, new_allocsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) {
                    perror("mmap failed");
                    goto MapError;
                }
                if (inbuf->_fd == -1) {
                    /* copy data (moving from malloc to mmap) */
                    newp->size = inbuf->size;
                    newp->bytes = newp->_buf;
                    newp->capacity = new_capacity;
                    newp->_prototype = inbuf->_prototype;
                    newp->_fd = fd;
                    memcpy(newp->_buf, inbuf->bytes, inbuf->size);
                    h2o_buffer__do_free(inbuf);
                    *_inbuf = inbuf = newp;
                } else {
                    /* munmap */
                    size_t offset = inbuf->bytes - inbuf->_buf;
                    munmap((void *)inbuf, topagesize(inbuf->capacity));
                    *_inbuf = inbuf = newp;
                    inbuf->capacity = new_capacity;
                    inbuf->bytes = newp->_buf + offset;
                }
            } else {
                auto newp = (h2o_buffer_t *)h2o_mem_alloc(offsetof(h2o_buffer_t, _buf) + new_capacity);
                newp->size = inbuf->size;
                newp->bytes = newp->_buf;
                newp->capacity = new_capacity;
                newp->_prototype = inbuf->_prototype;
                newp->_fd = -1;
                memcpy(newp->_buf, inbuf->bytes, inbuf->size);
                h2o_buffer__do_free(inbuf);
                *_inbuf = inbuf = newp;
            }
        }
    }

    ret.base = inbuf->bytes + inbuf->size;
    ret.len = inbuf->_buf + inbuf->capacity - ret.base;

    return ret;

MapError:
    ret.base = NULL;
    ret.len = 0;
    return ret;
#endif
}

void h2o_buffer_t::consume(size_t delta)
{
/*    if (delta != 0) {
        assert(this->bytes != NULL);
        if (this->size == delta) {
            *_inbuf = &this->_prototype->_initial_buf;
            h2o_buffer__do_free(this);
        } else {
            this->size -= delta;
            this->bytes += delta;
        }
    }*/
}

void h2o_buffer_t::dispose_linked(void *p)
{
    //auto buf = (h2o_buffer_t **)p;
    //h2o_buffer_dispose(buf);
}

void h2o_mem_swap(void *_x, void *_y, size_t len)
{
    auto x = (char*)_x, y = (char*)_y;
    char buf[256];

    while (len != 0) {
        size_t blocksz = len < sizeof(buf) ? len : sizeof(buf);
        memcpy(buf, x, blocksz);
        memcpy(x, y, blocksz);
        memcpy(y, buf, blocksz);
        len -= blocksz;
    }
}

void h2o_dump_memory(FILE *fp, const char *buf, size_t len)
{
    size_t i, j;

    for (i = 0; i < len; i += 16) {
        fprintf(fp, "%08zx", i);
        for (j = 0; j != 16; ++j) {
            if (i + j < len)
                fprintf(fp, " %02x", (int)(unsigned char)buf[i + j]);
            else
                fprintf(fp, "   ");
        }
        fprintf(fp, " ");
        for (j = 0; j != 16 && i + j < len; ++j) {
            int ch = buf[i + j];
            fputc(' ' <= ch && ch < 0x7f ? ch : '.', fp);
        }
        fprintf(fp, "\n");
    }
}

void h2o_append_to_null_terminated_list(void ***list, void *element)
{
    size_t cnt;

    for (cnt = 0; (*list)[cnt] != NULL; ++cnt)
        ;
    *list = h2o_mem_realloc_for<void*>(*list, (cnt + 2) * sizeof(void *));
    (*list)[cnt++] = element;
    (*list)[cnt] = NULL;
}
