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
#include <openssl/sha.h>
#include "golombset.h"
#include "h2o/string_.h"
#include "h2o/http2_casper.h"

#define COOKIE_NAME "h2o_casper"
#define COOKIE_ATTRIBUTES "; Path=/; Expires=Tue, 01 Jan 2030 00:00:00 GMT"


static unsigned calc_key(h2o_http2_casper_t *casper, const char *path,
        size_t path_len, const char *etag, size_t etag_len)
{
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, path, path_len);
    SHA1_Update(&ctx, etag, etag_len);

    union {
        unsigned key;
        unsigned char bytes[SHA_DIGEST_LENGTH];
    } md;
    SHA1_Final(md.bytes, &ctx);

    return md.key & ((1 << casper->capacity_bits) - 1);
}

h2o_http2_casper_t *h2o_http2_casper_t::create(unsigned capacity_bits,
        unsigned remainder_bits)
{
    auto casper = h2o_mem_alloc_for<h2o_http2_casper_t>();

    h2o_clearmem(&casper->keys);
    casper->capacity_bits = capacity_bits;
    casper->remainder_bits = remainder_bits;
    casper->cookie_cache = {};

    return casper;
}

void h2o_http2_casper_t::destroy(h2o_http2_casper_t *casper)
{
    h2o_mem_free(casper->keys.entries);
    h2o_mem_free(casper->cookie_cache.base);
    h2o_mem_free(casper);
}


int h2o_http2_casper_t::lookup(const char *path,
        size_t path_len, const char *etag, size_t etag_len, int set)
{
    unsigned key = calc_key(this, path, path_len, etag, etag_len);
    size_t i;

    /* FIXME use binary search */
    for (i = 0; i != keys.size; ++i)
        if (key <= keys[i])
            break;
    if (i != keys.size && key == keys[i])
        return 1;
    if (!set)
        return 0;

    /* we need to set a new value */
    h2o_mem_free(cookie_cache.base);
    cookie_cache = {};
    keys.push_front(NULL, key);
    return 0;
}

void h2o_http2_casper_t::consume_cookie(const char *cookie, size_t cookie_len)
{
    h2o_iovec_t binary = {};
    unsigned tiny_keys_buf[128], *keys = tiny_keys_buf;
    size_t capacity, num_keys;

    /* check the name of the cookie */
    if (!(cookie_len > sizeof(COOKIE_NAME "=") - 1 &&
            memcmp(cookie, H2O_STRLIT(COOKIE_NAME "=")) == 0))
        goto Exit;

    /* base64 decode */
    if ((binary = h2o_decode_base64url(NULL, cookie + sizeof(COOKIE_NAME "=")-1,
                cookie_len - (sizeof(COOKIE_NAME "=") - 1))).base == NULL)
        goto Exit;

    /* decode GCS, either using tiny_keys_buf or using heap */
    capacity = sizeof(tiny_keys_buf) / sizeof(tiny_keys_buf[0]);
    while (num_keys = capacity, golombset_decode(this->remainder_bits,
                binary.base, binary.len, keys, &num_keys) != 0) {
        if (keys != tiny_keys_buf) {
            h2o_mem_free(keys);
            keys = tiny_keys_buf; /* reset to something that would not trigger call to free(3) */
        }
        if (capacity >= (size_t)1 << this->capacity_bits)
            goto Exit;
        capacity *= 2;
        keys = h2o_mem_alloc_for<unsigned>(capacity);
    }

    /* copy or merge the entries */
    if (num_keys == 0) {
        /* nothing to do */
    } else if (this->keys.size == 0) {
        this->keys.assign_elements(NULL, keys, num_keys);
    } else {
        unsigned *orig_keys = this->keys.entries;
        size_t num_orig_keys = this->keys.size, orig_index = 0, new_index = 0;
        h2o_clearmem(&this->keys);
        this->keys.reserve(NULL, num_keys + num_orig_keys);
        do {
            if (orig_keys[orig_index] < keys[new_index]) {
                this->keys[this->keys.size++] = orig_keys[orig_index++];
            } else if (orig_keys[orig_index] > keys[new_index]) {
                this->keys[this->keys.size++] = keys[new_index++];
            } else {
                this->keys[this->keys.size++] = orig_keys[orig_index];
                ++orig_index;
                ++new_index;
            }
        } while (orig_index != num_orig_keys && new_index != num_keys);
        if (orig_index != num_orig_keys) {
            do {
                this->keys[this->keys.size++] = orig_keys[orig_index++];
            } while (orig_index != num_orig_keys);
        } else if (new_index != num_keys) {
            do {
                this->keys[this->keys.size++] = keys[new_index++];
            } while (new_index != num_keys);
        }
        h2o_mem_free(orig_keys);
    }

Exit:
    if (keys != tiny_keys_buf)
        h2o_mem_free(keys);
    h2o_mem_free(binary.base);
}

static size_t append_str(char *dst, const char *s, size_t l)
{
    memcpy(dst, s, l);
    return l;
}

h2o_iovec_t h2o_http2_casper_t::get_cookie()
{
    if (this->cookie_cache.base != NULL)
        return this->cookie_cache;

    if (this->keys.size == 0)
        return (h2o_iovec_t){};

    /* encode as binary */
    char tiny_bin_buf[128], *bin_buf = tiny_bin_buf;
    size_t bin_capacity = sizeof(tiny_bin_buf), bin_size;
    while (bin_size = bin_capacity,
           golombset_encode(this->remainder_bits, this->keys.entries,
           this->keys.size, bin_buf, &bin_size) != 0) {
        if (bin_buf != tiny_bin_buf)
            h2o_mem_free(bin_buf);
        bin_capacity *= 2;
        bin_buf = h2o_mem_alloc_for<char>(bin_capacity);
    }

    auto header_bytes = h2o_mem_alloc_for<char>(
        sizeof(COOKIE_NAME "=" COOKIE_ATTRIBUTES) - 1 + (bin_size + 3) * 4 / 3);
    size_t header_len = 0;

    header_len += append_str(header_bytes + header_len, H2O_STRLIT(COOKIE_NAME "="));
    header_len += h2o_base64_encode(header_bytes + header_len, bin_buf, bin_size, 1);
    header_len += append_str(header_bytes + header_len, H2O_STRLIT(COOKIE_ATTRIBUTES));

    if (bin_buf != tiny_bin_buf)
        h2o_mem_free(bin_buf);

    this->cookie_cache.init(header_bytes, header_len);
    return this->cookie_cache;
}
