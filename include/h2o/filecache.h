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
#ifndef h2o__filecache_h
#define h2o__filecache_h

#include <stddef.h>
#include <sys/stat.h>
#include <time.h>
#include "h2o/linklist.h"
#include "h2o/memory.h"
#include "h2o/time_.h"

#define H2O_FILECACHE_ETAG_MAXLEN (sizeof("\"deadbeef-deadbeefdeadbeef\"") - 1)

struct h2o_filecache_ref_t {
    int fd;
    size_t _refcnt;
    h2o_linklist_t _lru;
    union {
        struct {
            /* used if fd != -1 */
            struct stat st;
            struct {
                struct tm gm;
                char str[H2O_TIMESTR_RFC1123_LEN + 1];
            } _last_modified;
            struct {
                char buf[H2O_FILECACHE_ETAG_MAXLEN + 1];
                size_t len;
            } _etag;
        };
        /* used if fd != -1 */
        int open_err;
    };
    char _path[1];

    struct tm *get_last_modified(char *outbuf);
    size_t get_etag(char *outbuf);
};

struct h2o_filecache_t {
    void *hash_table;
    h2o_linklist_t lru;
    size_t capacity;

    static h2o_filecache_t *create(size_t capacity);
    static void destroy(h2o_filecache_t *cache);
    void clear();

    h2o_filecache_ref_t *open_file(const char *path, int oflag);
    static void close_file(h2o_filecache_ref_t *ref);
};


#endif
