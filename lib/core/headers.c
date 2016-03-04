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
#include <stddef.h>
#include <stdio.h>
#include "h2o.h"

h2o_header_t *h2o_headers_t::add(h2o_mem_pool_t *pool, h2o_iovec_t *name, const char *value,
                                size_t value_len)
{
    auto slot = this->append_new(pool);

    slot->name = name;
    slot->value.base = (char *)value;
    slot->value.len = value_len;

    return slot;
}

ssize_t h2o_headers_t::find(const h2o_token_t *token, size_t cursor)
{
    for (++cursor; cursor < this->size; ++cursor) {
        if (this->entries[cursor].name == &token->buf) {
            return cursor;
        }
    }
    return -1;
}

ssize_t h2o_headers_t::find(const char *name, size_t name_len, size_t cursor)
{
    for (++cursor; cursor < this->size; ++cursor) {
        auto t = this->entries[cursor];
        if (h2o_lcstris(name, name_len, t.name->base, t.name->len)) {
            return cursor;
        }
    }
    return -1;
}

void h2o_headers_t::add(h2o_mem_pool_t *pool, const h2o_token_t *token, const char *value, size_t value_len)
{
    this->add(pool, (h2o_iovec_t *)&token->buf, value, value_len);
}

void h2o_headers_t::add(h2o_mem_pool_t *pool, const char *name, size_t name_len, int maybe_token,
                           const char *value, size_t value_len)
{
    if (maybe_token) {
        auto token = h2o_lookup_token(name, name_len);
        if (token != NULL) {
            this->add(pool, (h2o_iovec_t *)token, value, value_len);
            return;
        }
    }
    auto name_buf = pool->alloc_for<h2o_iovec_t>();
    name_buf->base = (char *)name;
    name_buf->len = name_len;
    this->add(pool, name_buf, value, value_len);
}

void h2o_headers_t::set(h2o_mem_pool_t *pool, const h2o_token_t *token, const char *value, size_t value_len,
                    int overwrite_if_exists)
{
    ssize_t cursor = this->find(token, -1);
    if (cursor != -1) {
        if (overwrite_if_exists) {
            auto slot = &this->entries[cursor].value;
            slot->base = (char *)value;
            slot->len = value_len;
        }
    } else {
        this->add(pool, token, value, value_len);
    }
}

void h2o_headers_t::set(h2o_mem_pool_t *pool, const char *name, size_t name_len, int maybe_token,
                           const char *value, size_t value_len, int overwrite_if_exists)
{
    if (maybe_token) {
        auto token = h2o_lookup_token(name, name_len);
        if (token != NULL) {
            this->set(pool, token, value, value_len, overwrite_if_exists);
            return;
        }
    }

    auto cursor = this->find(name, name_len, -1);
    if (cursor != -1) {
        if (overwrite_if_exists) {
            auto slot = &this->entries[cursor].value;
            slot->base = (char *)value;
            slot->len = value_len;
        }
    } else {
        auto name_buf = pool->alloc_for<h2o_iovec_t>();
        name_buf->base = (char *)name;
        name_buf->len = name_len;
        this->add(pool, name_buf, value, value_len);
    }
}

void h2o_headers_t::add_token(h2o_mem_pool_t *pool, const h2o_token_t *token, const char *value,
                          size_t value_len)
{
    auto cursor = this->find(token, -1);
    if (cursor != -1) {
        h2o_iovec_t src = this->entries[cursor].value, dst;
        dst.len = src.len + value_len + 2;
        dst.base = pool->alloc_for<char>(dst.len + 1);
        dst.base[dst.len] = '\0';
        memcpy(dst.base, src.base, src.len);
        dst.base[src.len] = ',';
        dst.base[src.len + 1] = ' ';
        memcpy(dst.base + src.len + 2, value, value_len);
        this->entries[cursor].value = dst;
    } else {
        this->add(pool, token, value, value_len);
    }
}
