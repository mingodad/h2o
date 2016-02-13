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
#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include "khash.h"
#include "h2o/memory.h"
#include "h2o/filecache.h"

KHASH_SET_INIT_STR(opencache_set);


static inline void release_from_cache(h2o_filecache_t *cache, khiter_t iter)
{
    auto hash = (khash_t(opencache_set)*)cache->hash_table;
    const char *path = kh_key(hash, iter);
    auto ref = H2O_STRUCT_FROM_MEMBER(h2o_filecache_ref_t, _path, path);

    /* detach from list */
    kh_del(opencache_set, hash, iter);
    ref->_lru.unlink();

    /* and close */
    cache->close_file(ref);
}

h2o_filecache_t *h2o_filecache_t::create(size_t capacity)
{
    auto cache = h2o_mem_alloc_for<h2o_filecache_t>();

    cache->hash_table = kh_init(opencache_set);
    cache->lru.init_anchor();
    cache->capacity = capacity;

    return cache;
}

void h2o_filecache_t::destroy(h2o_filecache_t *cache)
{
    cache->clear();
    auto hash = (khash_t(opencache_set)*)cache->hash_table;
    assert(kh_size(hash) == 0);
    assert(cache->lru.is_empty());
    kh_destroy(opencache_set, hash);
    h2o_mem_free(cache);
}

void h2o_filecache_t::clear()
{
    khiter_t iter;
    auto hash = (khash_t(opencache_set)*)this->hash_table;
    for (iter = kh_begin(hash); iter != kh_end(hash); ++iter) {
        if (!kh_exist(hash, iter))
            continue;
        release_from_cache(this, iter);
    }
    assert(kh_size(hash) == 0);
}

h2o_filecache_ref_t *h2o_filecache_t::open_file(const char *path, int oflag)
{
    auto hash = (khash_t(opencache_set)*)this->hash_table;
    khiter_t iter = kh_get(opencache_set, hash, path);
    h2o_filecache_ref_t *ref;
    int fd, dummy;

    /* lookup cache, and return the one if found */
    if (iter != kh_end(hash)) {
        ref = H2O_STRUCT_FROM_MEMBER(h2o_filecache_ref_t, _path, kh_key(hash, iter));
        ++ref->_refcnt;
        return ref;
    }

    /* not found, try to open the new file */
    if ((fd = open(path, oflag)) == -1)
        return NULL;
    ref = (h2o_filecache_ref_t *)h2o_mem_alloc(offsetof(h2o_filecache_ref_t, _path) + strlen(path) + 1);
    if (fstat(fd, &ref->st) != 0) {
        close(fd);
        h2o_mem_free(ref);
        return NULL;
    }
    ref->fd = fd;
    ref->_last_modified.str[0] = '\0';
    ref->_etag.len = 0;
    ref->_refcnt = 1;
    ref->_lru = {};
    strcpy(ref->_path, path);
    /* if cache is used, then... */
    if (this->capacity != 0) {
        /* purge one entry from LRU if cache is full */
        if (kh_size(hash) == this->capacity) {
            auto purge_ref = H2O_STRUCT_FROM_MEMBER(h2o_filecache_ref_t, _lru, lru.prev);
            khiter_t purge_iter = kh_get(opencache_set, hash, purge_ref->_path);
            assert(purge_iter != kh_end(hash));
            release_from_cache(this, purge_iter);
        }
        /* assign the new entry */
        ++ref->_refcnt;
        kh_put(opencache_set, hash, ref->_path, &dummy);
        this->lru.next->insert(&ref->_lru);
    }

    return ref;
}

void h2o_filecache_t::close_file(h2o_filecache_ref_t *ref)
{
    if (--ref->_refcnt != 0)
        return;
    assert(!ref->_lru.is_linked());
    close(ref->fd);
    ref->fd = -1;
    h2o_mem_free(ref);
}

struct tm *h2o_filecache_ref_t::get_last_modified(char *outbuf)
{
    if (this->_last_modified.str[0] == '\0') {
        gmtime_r(&this->st.st_mtime, &this->_last_modified.gm);
        h2o_time2str_rfc1123(this->_last_modified.str, &this->_last_modified.gm);
    }
    if (outbuf != NULL)
        memcpy(outbuf, this->_last_modified.str, H2O_TIMESTR_RFC1123_LEN + 1);
    return &this->_last_modified.gm;
}

size_t h2o_filecache_ref_t::get_etag(char *outbuf)
{
    if (this->_etag.len == 0)
        this->_etag.len = snprintf(this->_etag.buf, sizeof(this->_etag.buf), "\"%08x-%zx\"", (unsigned)this->st.st_mtime, (size_t)this->st.st_size);
    memcpy(outbuf, this->_etag.buf, this->_etag.len + 1);
    return this->_etag.len;
}
