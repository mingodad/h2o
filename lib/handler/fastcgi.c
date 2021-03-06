/*
 * Copyright (c) 2015-2016 DeNA Co., Ltd. Kazuho Oku
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
#include <inttypes.h>
#include <stdio.h>
#include "h2o/httpparser.h"
#include "h2o.h"

#define FCGI_VERSION_1 1

#define FCGI_RESPONDER 1
#define FCGI_KEEP_CONN 1

#define FCGI_BEGIN_REQUEST 1
#define FCGI_END_REQUEST 3
#define FCGI_PARAMS 4
#define FCGI_STDIN 5
#define FCGI_STDOUT 6
#define FCGI_STDERR 7
#define FCGI_DATA 8

#define FCGI_RECORD_HEADER_SIZE (sizeof(fcgi_record_header_t))
#define FCGI_BEGIN_REQUEST_BODY_SIZE 8

#define MODULE_NAME "lib/handler/fastcgi.c"

#define APPEND_BLOCKSIZE 512 /* the size should be small enough to be allocated within the buffer of the memory pool */

struct fcgi_record_header_t {
    uint8_t version;
    uint8_t type;
    uint16_t requestId;
    uint16_t contentLength;
    uint8_t paddingLength;
    uint8_t reserved;
};

struct fcgi_begin_request_body_t {
    uint16_t role;
    uint8_t flags;
    uint8_t reserved[5];
};

typedef H2O_VECTOR<h2o_iovec_t> iovec_vector_t;

struct fcgi_context_t {
    h2o_fastcgi_handler_t *handler;
    h2o_timeout_t io_timeout;
};

struct fcgi_generator_t {
    h2o_generator_t super;
    fcgi_context_t *ctx;
    h2o_req_t *req;
    h2o_socketpool_connect_request_t *connect_req;
    h2o_socket_t *sock;
    int sent_headers;
    size_t leftsize; /* remaining amount of the content to receive (or SIZE_MAX if unknown) */
    struct {
        h2o_doublebuffer_t sending;
        h2o_buffer_t *receiving;
    } resp;
    h2o_timeout_entry_t timeout;
};

struct h2o_fastcgi_handler_t : h2o_handler_t {
    h2o_socketpool_t sockpool;
    h2o_fastcgi_config_vars_t config;

    h2o_fastcgi_handler_t(): sockpool({}), config({}) {}

    void on_context_init(h2o_context_t *ctx) override;
    void on_context_dispose(h2o_context_t *ctx) override;
    void dispose(h2o_base_handler_t *self) override;
};

static void encode_uint16(void *_p, unsigned v) {
    auto p = (unsigned char *)_p;
    p[0] = (unsigned char) (v >> 8);
    p[1] = (unsigned char) v;
}

static void encode_record_header(void *p, uint8_t type, uint16_t reqId, uint16_t sz) {
    auto header = (fcgi_record_header_t*)p;
    header->version = FCGI_VERSION_1;
    header->type = type;
    encode_uint16(&header->requestId, reqId);
    encode_uint16(&header->contentLength, sz);
    header->paddingLength = 0;
    header->reserved = 0;
}

static void encode_begin_request(void *p, uint16_t reqId, uint16_t role, uint8_t flags) {
    encode_record_header(p, FCGI_BEGIN_REQUEST, reqId, FCGI_BEGIN_REQUEST_BODY_SIZE);
    auto body = (fcgi_begin_request_body_t *) ((char *) p + FCGI_RECORD_HEADER_SIZE);
    encode_uint16(&body->role, role);
    body->flags = flags;
    //h2o_clearmem do not work here because it's a char array
	memset(body->reserved, 0, sizeof(body->reserved));
}

static h2o_iovec_t create_begin_request(h2o_mem_pool_t *pool, uint16_t reqId,
        uint16_t role, uint8_t flags) {
    const size_t sz = FCGI_RECORD_HEADER_SIZE + FCGI_BEGIN_REQUEST_BODY_SIZE;
    h2o_iovec_t rec = h2o_iovec_t::create(pool->alloc(sz), sz);
    encode_begin_request(rec.base, reqId, role, flags);
    return rec;
}

static h2o_iovec_t create_header(h2o_mem_pool_t *pool, uint8_t type,
        uint16_t reqId, uint16_t sz) {
    h2o_iovec_t rec = h2o_iovec_t::create(pool->alloc(
            FCGI_RECORD_HEADER_SIZE), FCGI_RECORD_HEADER_SIZE);
    encode_record_header(rec.base, type, reqId, sz);
    return rec;
}

static void decode_header(fcgi_record_header_t *decoded, const void *s) {
    memcpy(decoded, s, sizeof (*decoded));
    decoded->requestId = htons(decoded->requestId);
    decoded->contentLength = htons(decoded->contentLength);
}

static void *append(h2o_mem_pool_t *pool, iovec_vector_t *blocks,
        const void *s, size_t len) {
    h2o_iovec_t *slot;

    if (blocks->entries[blocks->size - 1].len + len > APPEND_BLOCKSIZE) {
        slot = blocks->append_new(pool);
        slot->base = pool->alloc_for<char>(len < APPEND_BLOCKSIZE ? APPEND_BLOCKSIZE : len);
        slot->len = 0;
    } else {
        slot = blocks->entries + blocks->size - 1;
    }

    if (s != NULL)
        memcpy(slot->base + slot->len, s, len);
    slot->len += len;

    return slot->base + slot->len - len;
}

static char *encode_length_of_pair(char *p, size_t len) {
    if (len < 127) {
        *p++ = (char) len;
    } else {
        *p++ = (unsigned char) (len >> 24) | 0x80;
        *p++ = (unsigned char) (len >> 16);
        *p++ = (unsigned char) (len >> 8);
        *p++ = (unsigned char) len;
    }
    return p;
}

static void *append_pair(h2o_mem_pool_t *pool, iovec_vector_t *blocks,
        const char *name, size_t namelen, const char *value, size_t valuelen) {
    char lenbuf[8];
    void *name_buf;

    append(pool, blocks, lenbuf, encode_length_of_pair(
            encode_length_of_pair(lenbuf, namelen), valuelen) - lenbuf);
    name_buf = append(pool, blocks, name, namelen);
    if (valuelen != 0)
        append(pool, blocks, value, valuelen);

    return name_buf;
}
#define append_pair_pv(iov1, iov2) \
    append_pair(&req->pool, vecs, iov1.base, iov1.len, iov2.base, iov2.len)
#define append_pair_pvlv(literal, iov2) \
    append_pair(&req->pool, vecs, H2O_STRLIT(literal), iov2.base, iov2.len)

static void append_address_info(h2o_req_t *req, iovec_vector_t *vecs,
        const char *addrlabel, size_t addrlabel_len,
        const char *portlabel, size_t portlabel_len,
        h2o_get_address_info_cb cb) {
    h2o_socket_address remote_addr = {};

    if(h2o_get_address_info(remote_addr, req->conn, cb))
        return;

    if (remote_addr.remote_addr_len)
        append_pair(&req->pool, vecs, addrlabel, addrlabel_len,
                    remote_addr.remote_addr, remote_addr.remote_addr_len);
    if (remote_addr.port) {
        int l = sprintf(remote_addr.remote_addr, "%" PRIu16, remote_addr.port);
        append_pair(&req->pool, vecs, portlabel, portlabel_len, remote_addr.remote_addr, (size_t) l);
    }
}

static void append_params(h2o_req_t *req, iovec_vector_t *vecs,
        h2o_fastcgi_config_vars_t *config) {
    h2o_iovec_t path_info = {};

    /* CONTENT_LENGTH */
    if (req->entity.base != NULL) {
        char buf[32];
        int l = sprintf(buf, "%zu", req->entity.len);
        append_pair(&req->pool, vecs, H2O_STRLIT("CONTENT_LENGTH"), buf, (size_t) l);
    }
    /* SCRIPT_FILENAME, SCRIPT_NAME, PATH_INFO */
    if (req->filereq != NULL) {
        h2o_filereq_t *filereq = req->filereq;
        append_pair(&req->pool, vecs, H2O_STRLIT("SCRIPT_FILENAME"), filereq->local_path.base, filereq->local_path.len);
        append_pair(&req->pool, vecs, H2O_STRLIT("SCRIPT_NAME"), req->path_normalized.base, filereq->url_path_len);
        if (req->path_normalized.len != filereq->url_path_len)
            path_info.init(req->path_normalized.base + filereq->url_path_len,
                req->path_normalized.len - filereq->url_path_len);
    } else {
        append_pair(&req->pool, vecs, H2O_STRLIT("SCRIPT_NAME"), NULL, 0);
        path_info = req->path_normalized;
    }
    if (path_info.base != NULL)
        append_pair_pvlv("PATH_INFO", path_info);
    /* DOCUMENT_ROOT and PATH_TRANSLATED */
    if (config->document_root.base != NULL) {
        append_pair_pvlv("DOCUMENT_ROOT", config->document_root);
        if (path_info.base != NULL) {
            append_pair(&req->pool, vecs, H2O_STRLIT("PATH_TRANSLATED"), NULL,
                    config->document_root.len + path_info.len);
            char *dst_end = vecs->entries[vecs->size - 1].base +
                    vecs->entries[vecs->size - 1].len;
            memcpy(dst_end - path_info.len, path_info.base, path_info.len);
            memcpy(dst_end - path_info.len - config->document_root.len,
                    config->document_root.base, config->document_root.len);
        }
    }
    /* QUERY_STRING (and adjust PATH_INFO) */
    if (req->query_at != SIZE_MAX) {
        append_pair(&req->pool, vecs, H2O_STRLIT("QUERY_STRING"),
                req->path.base + req->query_at + 1,
                req->path.len - (req->query_at + 1));
    } else {
        append_pair(&req->pool, vecs, H2O_STRLIT("QUERY_STRING"), NULL, 0);
    }
    /* REMOTE_ADDR & REMOTE_PORT */
    append_address_info(req, vecs, H2O_STRLIT("REMOTE_ADDR"),
            H2O_STRLIT("REMOTE_PORT"), req->conn->callbacks->get_peername);
    /* REMOTE_USER */
    if (req->remote_user.base != NULL)
        append_pair(&req->pool, vecs, H2O_STRLIT("REMOTE_USER"), req->remote_user.base, req->remote_user.len);
    /* REQUEST_METHOD */
    append_pair_pvlv("REQUEST_METHOD", req->method);
    /* HTTP_HOST & REQUEST_URI */
    if (config->send_delegated_uri) {
        append_pair_pvlv("HTTP_HOST", req->authority);
        append_pair_pvlv("REQUEST_URI", req->path);
    } else {
        append_pair_pvlv("HTTP_HOST", req->input.authority);
        append_pair_pvlv("REQUEST_URI", req->input.path);
    }
    /* SERVER_ADDR & SERVER_PORT */
    append_address_info(req, vecs, H2O_STRLIT("SERVER_ADDR"),
            H2O_STRLIT("SERVER_PORT"), req->conn->callbacks->get_sockname);
    /* SERVER_NAME */
    append_pair_pvlv("SERVER_NAME", req->hostconf->authority.host);
    { /* SERVER_PROTOCOL */
        char buf[sizeof ("HTTP/1.1")];
        size_t l = h2o_stringify_protocol_version(buf, req->version);
        append_pair(&req->pool, vecs, H2O_STRLIT("SERVER_PROTOCOL"), buf, l);
    }
    /* SERVER_SOFTWARE */
    append_pair_pvlv("SERVER_SOFTWARE", req->conn->ctx->globalconf->server_name);
    /* set HTTPS: on if necessary */
    if (req->scheme == &H2O_URL_SCHEME_HTTPS)
        append_pair(&req->pool, vecs, H2O_STRLIT("HTTPS"), H2O_STRLIT("on"));
    { /* headers */
        const h2o_header_t *h = req->headers.entries, *h_end = h + req->headers.size;
        size_t cookie_length = 0;
        for (; h != h_end; ++h) {
            if (h->name == &H2O_TOKEN_CONTENT_TYPE->buf) {
                append_pair_pvlv("CONTENT_TYPE", h->value);
            } else if (h->name == &H2O_TOKEN_COOKIE->buf) {
                /* accumulate the length of the cookie, together with the separator */
                cookie_length += h->value.len + 1;
            } else {
                char *dst = (char*)append_pair(&req->pool, vecs, NULL,
                        h->name->len + sizeof ("HTTP_") - 1, h->value.base, h->value.len);
                const char *src = h->name->base, *src_end = src + h->name->len;
                *dst++ = 'H';
                *dst++ = 'T';
                *dst++ = 'T';
                *dst++ = 'P';
                *dst++ = '_';
                for (; src != src_end; ++src)
                    *dst++ = *src == '-' ? '_' : h2o_toupper(*src);
            }
        }
        if (cookie_length != 0) {
            /* emit the cookie merged */
            cookie_length -= 1;
            append_pair(&req->pool, vecs, H2O_STRLIT("HTTP_COOKIE"), NULL, cookie_length);
            char *dst = vecs->entries[vecs->size - 1].base +
                    vecs->entries[vecs->size - 1].len - cookie_length;
            for (h = req->headers.entries;; ++h) {
                if (h->name == &H2O_TOKEN_COOKIE->buf) {
                    if (cookie_length == h->value.len)
                        break;
                    memcpy(dst, h->value.base, h->value.len);
                    dst += h->value.len;
                    *dst++ = ';';
                    cookie_length -= h->value.len + 1;
                }
            }
            memcpy(dst, h->value.base, h->value.len);
        }
    }
}

static void annotate_params(h2o_mem_pool_t *pool, iovec_vector_t *vecs,
        unsigned request_id, size_t max_record_size) {
    size_t index = 2, recsize = 0, header_slot = 1;

    while (index != vecs->size) {
        if (recsize + vecs->entries[index].len < max_record_size) {
            recsize += vecs->entries[index].len;
            ++index;
        } else {
            vecs->entries[header_slot] = create_header(pool, FCGI_PARAMS,
                    request_id, max_record_size);
            if (recsize + vecs->entries[index].len == max_record_size) {
                vecs->reserve_more(pool, 1);
                memmove(vecs->entries + index + 2, vecs->entries + index + 1,
                        (vecs->size - (index + 1)) * sizeof (vecs->entries[0]));
                ++vecs->size;
            } else {
                vecs->reserve_more(pool, 2);
                memmove(vecs->entries + index + 2, vecs->entries + index,
                        (vecs->size - index) * sizeof (vecs->entries[0]));
                vecs->size += 2;
                size_t lastsz = max_record_size - recsize;
                vecs->entries[index].len = lastsz;
                vecs->entries[index + 2].base += lastsz;
                vecs->entries[index + 2].len -= lastsz;
            }
            header_slot = index + 1;
            index += 2;
            recsize = 0;
        }
    }

    vecs->entries[header_slot] = create_header(pool, FCGI_PARAMS, request_id, recsize);
    if (recsize != 0) {
        vecs->push_back(pool, create_header(pool, FCGI_PARAMS, request_id, 0));
    }
}

static void build_request(h2o_req_t *req, iovec_vector_t *vecs,
        unsigned request_id, size_t max_record_size,
        h2o_fastcgi_config_vars_t *config) {
    vecs->reset();

    /* first entry is FCGI_BEGIN_REQUEST */
    vecs->reserve(&req->pool, 5 /* we send at least 5 iovecs */);
    vecs->entries[0] =
            create_begin_request(&req->pool, request_id, FCGI_RESPONDER,
            config->keepalive_timeout != 0 ? FCGI_KEEP_CONN : 0);
    /* second entry is reserved for FCGI_PARAMS header */
    vecs->entries[1].init(NULL, APPEND_BLOCKSIZE); /* dummy value set to prevent params being appended to the entry */
    vecs->size = 2;
    /* accumulate the params data, and annotate them with FCGI_PARAM headers */
    append_params(req, vecs, config);
    annotate_params(&req->pool, vecs, request_id, max_record_size);
    /* setup FCGI_STDIN headers */
    if (req->entity.len != 0) {
        size_t off = 0;
        for (; off + max_record_size < req->entity.len; off += max_record_size) {
            vecs->reserve_more(&req->pool, 2);
            vecs->entries[vecs->size++] = create_header(&req->pool, FCGI_STDIN, request_id, max_record_size);
            vecs->entries[vecs->size++].init(req->entity.base + off, max_record_size);
        }
        if (off != req->entity.len) {
            vecs->reserve_more(&req->pool, 2);
            vecs->entries[vecs->size++] = create_header(&req->pool, FCGI_STDIN, request_id, req->entity.len - off);
            vecs->entries[vecs->size++].init(req->entity.base + off, req->entity.len - off);
        }
    }
    vecs->push_back(&req->pool, create_header(&req->pool, FCGI_STDIN, request_id, 0));
}

static void set_timeout(fcgi_generator_t *generator, h2o_timeout_t *timeout, h2o_timeout_cb cb) {
    generator->timeout.stop();

    generator->timeout.cb = cb;
    generator->timeout.data = generator;
    timeout->start(generator->req->conn->ctx->loop, &generator->timeout);
}

static void close_generator(fcgi_generator_t *generator) {
    /* can be called more than once */

    generator->timeout.stop();
    if (generator->connect_req != NULL) {
        h2o_socketpool_cancel_connect(generator->connect_req);
        generator->connect_req = NULL;
    }
    if (generator->sock != NULL) {
        h2o_socket_t::close(generator->sock);
        generator->sock = NULL;
    }
    if (generator->resp.sending.buf != NULL)
        h2o_doublebuffer_dispose(&generator->resp.sending);
    if (generator->resp.receiving != NULL)
        h2o_buffer_dispose(&generator->resp.receiving);
}

static void do_send(fcgi_generator_t *generator) {
    h2o_iovec_t vecs[1];
    size_t veccnt;
    int is_final;

    vecs[0] = h2o_doublebuffer_prepare(&generator->resp.sending,
            &generator->resp.receiving, generator->req->preferred_chunk_size);
    veccnt = vecs[0].len != 0 ? 1 : 0;
    if (generator->sock == NULL && vecs[0].len == generator->resp.sending.buf->size &&
            generator->resp.receiving->size == 0) {
        is_final = 1;
        if (!(generator->leftsize == 0 || generator->leftsize == SIZE_MAX))
            generator->req->http1_is_persistent = 0;
    } else {
        if (veccnt == 0)
            return;
        is_final = 0;
    }
    generator->req->send(vecs, veccnt, is_final);
}

static void send_eos_and_close(fcgi_generator_t *generator, int can_keepalive) {
    if (generator->ctx->handler->config.keepalive_timeout != 0 && can_keepalive)
        h2o_socketpool_return(&generator->ctx->handler->sockpool, generator->sock);
    else
        h2o_socket_t::close(generator->sock);
    generator->sock = NULL;

    generator->timeout.stop();

    if (generator->resp.sending.bytes_inflight == 0)
        do_send(generator);
}

static void errorclose(fcgi_generator_t *generator) {
    if (generator->sent_headers) {
        send_eos_and_close(generator, 0);
    } else {
        h2o_req_t *req = generator->req;
        close_generator(generator);
        req->send_error(503, "Internal Server Error", "Internal Server Error", 0);
    }
}

static int _isdigit(int ch) {
    return '0' <= ch && ch <= '9';
}

static int fill_headers(h2o_req_t *req, phr_header *headers, size_t num_headers) {
    size_t i;

    /* set the defaults */
    req->res.status = 200;
    req->res.reason = "OK";
    req->res.content_length = SIZE_MAX;

    for (i = 0; i != num_headers; ++i) {
        const h2o_token_t *token;
        h2o_phr_headertolower(headers[i]);
        if ((token = h2o_lookup_token(headers[i].name, headers[i].name_len)) != NULL) {
            if (token->proxy_should_drop) {
                /* skip */
            } else if (token == H2O_TOKEN_CONTENT_LENGTH) {
                if (req->res.content_length != SIZE_MAX) {
                    req->log_error(MODULE_NAME, "received multiple content-length headers from fcgi");
                    return -1;
                }
                if ((req->res.content_length = h2o_pht_header_value_tosize(headers[i])) == SIZE_MAX) {
                    req->log_error(MODULE_NAME, "failed to parse content-length header sent from fcgi: %.*s",
                            (int) headers[i].value_len, headers[i].value);
                    return -1;
                }
            } else {
                /*
                RFC 3875 defines three headers to have special meaning: Content-Type, Status, Location.
                Status is handled as below.
                Content-Type does not seem to have any need to be handled specially.
                RFC suggests abs-path-style Location headers should trigger an internal redirection, but is that how the web servers
                work?
                 */
                req->addResponseHeader(token, h2o_strdup(&req->pool, headers[i].value, headers[i].value_len));
                if (token == H2O_TOKEN_LINK)
                    req->puth_path_in_link_header(headers[i].value, headers[i].value_len);
            }
        } else if (h2o_phr_header_name_is_literal(headers[i], "status")) {
            h2o_iovec_t value = h2o_iovec_t::create(headers[i].value, headers[i].value_len);
            if (value.len < 3 || !(_isdigit(value.base[0]) && _isdigit(value.base[1]) && _isdigit(value.base[2])) ||
                    (value.len >= 4 && value.base[3] != ' ')) {
                req->log_error(MODULE_NAME, "failed to parse Status header, got: %.*s", (int) value.len, value.base);
                return -1;
            }
            req->res.status = (value.base[0] - '0') * 100 + (value.base[1] - '0') * 10 + (value.base[2] - '0');
            req->res.reason = value.len >= 5 ? h2o_strdup(&req->pool, value.base + 4, value.len - 4).base : "OK";
        } else {
            h2o_iovec_t name_duped = h2o_strdup(&req->pool, headers[i].name, headers[i].name_len),
                    value_duped = h2o_strdup(&req->pool, headers[i].value, headers[i].value_len);
            req->res.headers.add(&req->pool, name_duped.base, name_duped.len, 0, value_duped.base,
                    value_duped.len);
        }
    }

    return 0;
}

static void append_content(fcgi_generator_t *generator, const void *src, size_t len) {
    /* do not accumulate more than content-length bytes */
    if (generator->leftsize != SIZE_MAX) {
        if (generator->leftsize < len) {
            len = generator->leftsize;
            if (len == 0)
                return;
        }
        generator->leftsize -= len;
    }

    h2o_buffer_append(&generator->resp.receiving, src, len);
}

static int handle_stdin_record(fcgi_generator_t *generator, fcgi_record_header_t *header) {
    h2o_buffer_t *input = generator->sock->input;
    struct phr_header headers[H2O_MAX_HEADERS];
    size_t num_headers;
    int parse_result;

    if (header->contentLength == 0)
        return 0;

    if (generator->sent_headers) {
        /* simply accumulate the data to response buffer */
        append_content(generator, input->bytes + FCGI_RECORD_HEADER_SIZE, header->contentLength);
        return 0;
    }

    /* parse the headers using the input buffer (or keep it in response buffer and parse) */
    num_headers = sizeof (headers) / sizeof (headers[0]);
    if (generator->resp.receiving->size == 0) {
        parse_result = phr_parse_headers(input->bytes + FCGI_RECORD_HEADER_SIZE,
                input->size, headers, &num_headers, 0);
    } else {
        size_t prevlen = generator->resp.receiving->size;
        memcpy(h2o_buffer_reserve(&generator->resp.receiving,
                header->contentLength).base,
                input->bytes + FCGI_RECORD_HEADER_SIZE,
                header->contentLength);
        generator->resp.receiving->size = prevlen + header->contentLength;
        parse_result =
                phr_parse_headers(generator->resp.receiving->bytes,
                generator->resp.receiving->size, headers, &num_headers, prevlen);
    }
    if (parse_result < 0) {
        if (parse_result == -2) {
            /* incomplete */
            return 0;
        } else {
            generator->req->log_error(MODULE_NAME, "received broken response");
            return -1;
        }
    }

    /* fill-in the headers, and start the response */
    if (fill_headers(generator->req, headers, num_headers) != 0)
        return -1;
    generator->leftsize = generator->req->res.content_length;
    generator->req->start_response(&generator->super);
    generator->sent_headers = 1;

    /* rest of the contents should be stored in the response buffer */
    if (generator->resp.receiving->size == 0) {
        size_t leftlen = header->contentLength - parse_result;
        if (leftlen != 0) {
            append_content(generator, input->bytes + FCGI_RECORD_HEADER_SIZE + parse_result, leftlen);
        }
    } else {
        h2o_buffer_consume(&generator->resp.receiving, parse_result);
    }

    return 0;
}

static void on_rw_timeout(h2o_timeout_entry_t *entry) {
    auto generator = (fcgi_generator_t*)entry->data;

    generator->req->log_error(MODULE_NAME, "I/O timeout");
    errorclose(generator);
}

static void on_read(h2o_socket_t *sock, int status) {
    auto generator = (fcgi_generator_t*)sock->data;
    int can_keepalive = 0;

    if (status != 0) {
        /* note: FastCGI server is allowed to close the connection any time after sending an empty FCGI_STDOUT record */
        if (!generator->sent_headers)
            generator->req->log_error(MODULE_NAME, "fastcgi connection closed unexpectedly");
        errorclose(generator);
        return;
    }

    /* handle the records */
    while (1) {
        fcgi_record_header_t header;
        size_t recsize;
        if (sock->input->size < FCGI_RECORD_HEADER_SIZE)
            break;
        decode_header(&header, sock->input->bytes);
        recsize = FCGI_RECORD_HEADER_SIZE + header.contentLength + header.paddingLength;
        if (sock->input->size < recsize)
            break;
        /* we have a complete record */
        switch (header.type) {
            case FCGI_STDOUT:
                if (handle_stdin_record(generator, &header) != 0)
                    goto Error;
                h2o_buffer_consume(&sock->input, recsize);
                break;
            case FCGI_STDERR:
                if (header.contentLength != 0)
                    generator->req->log_error(MODULE_NAME, "%.*s", (int) header.contentLength,
                        sock->input->bytes + FCGI_RECORD_HEADER_SIZE);
                h2o_buffer_consume(&sock->input, recsize);
                break;
            case FCGI_END_REQUEST:
                if (!generator->sent_headers) {
                    generator->req->log_error(MODULE_NAME, "received FCGI_END_REQUEST before end of the headers");
                    goto Error;
                }
                h2o_buffer_consume(&sock->input, recsize);
                can_keepalive = 1;
                goto EOS_Received;
            default:
                generator->req->log_error(MODULE_NAME, "received unexpected record, type: %u", header.type);
                h2o_buffer_consume(&sock->input, recsize);
                if (!generator->sent_headers)
                    goto Error;
                goto EOS_Received;
        }
    }

    /* send data if necessary */
    if (generator->sent_headers && generator->resp.sending.bytes_inflight == 0)
        do_send(generator);

    set_timeout(generator, &generator->ctx->io_timeout, on_rw_timeout);
    return;

EOS_Received:
    send_eos_and_close(generator, can_keepalive);
    return;

Error:
    errorclose(generator);
}

static void on_send_complete(h2o_socket_t *sock, int status) {
    auto generator = (fcgi_generator_t*)sock->data;

    set_timeout(generator, &generator->ctx->io_timeout, on_rw_timeout);
    /* do nothing else!  all the rest is handled by the on_read */
}

static void on_connect(h2o_socket_t *sock, const char *errstr, void *data) {
    auto generator = (fcgi_generator_t*)data;
    iovec_vector_t vecs;

    generator->connect_req = NULL;

    if (sock == NULL) {
        generator->req->log_error(MODULE_NAME, "connection failed:%s", errstr);
        errorclose(generator);
        return;
    }

    generator->sock = sock;
    sock->data = generator;

    build_request(generator->req, &vecs, 1, 65535, &generator->ctx->handler->config);

    /* start sending the response */
    generator->sock->write(vecs.entries, vecs.size, on_send_complete);

    set_timeout(generator, &generator->ctx->io_timeout, on_rw_timeout);

    /* activate the receiver; note: FCGI spec allows the app to start sending the response before it receives FCGI_STDIN */
    sock->read_start(on_read);
}

static void do_proceed(h2o_generator_t *_generator, h2o_req_t *req) {
    auto generator = (fcgi_generator_t *) _generator;

    h2o_doublebuffer_consume(&generator->resp.sending);
    do_send(generator);
}

static void do_stop(h2o_generator_t *_generator, h2o_req_t *req) {
    auto generator = (fcgi_generator_t *) _generator;
    close_generator(generator);
}

static void on_connect_timeout(h2o_timeout_entry_t *entry) {
    auto generator = (fcgi_generator_t*)entry->data;

    generator->req->log_error(MODULE_NAME, "connect timeout");
    errorclose(generator);
}

static int on_req(h2o_handler_t *_handler, h2o_req_t *req) {
    auto handler = (h2o_fastcgi_handler_t *) _handler;

    auto generator = req->pool.alloc_shared_for<fcgi_generator_t>(1, (mem_pool_dispose_cb_t)close_generator);
    generator->super.proceed = do_proceed;
    generator->super.stop = do_stop;
    generator->ctx = (fcgi_context_t*)req->conn->ctx->get_handler_context(handler);
    generator->req = req;
    generator->sock = NULL;
    generator->sent_headers = 0;
    h2o_doublebuffer_init(&generator->resp.sending, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&generator->resp.receiving, &h2o_socket_buffer_prototype);
    generator->timeout = {};

    set_timeout(generator, &generator->ctx->io_timeout, on_connect_timeout);
    h2o_socketpool_connect(&generator->connect_req, &handler->sockpool, req->conn->ctx->loop,
            &req->conn->ctx->receivers.hostinfo_getaddr, on_connect, generator);

    return 0;
}

void h2o_fastcgi_handler_t::on_context_init(h2o_context_t *ctx) {
    auto handler_ctx = h2o_mem_calloc_for<fcgi_context_t>();

    /* use the first event loop for handling timeouts of the socket pool */
    if (this->sockpool.timeout == UINT64_MAX)
        h2o_socketpool_set_timeout(&this->sockpool, ctx->loop,
            this->config.keepalive_timeout != 0 ? this->config.keepalive_timeout : 60000);

    handler_ctx->handler = this;
    handler_ctx->io_timeout.init(ctx->loop, this->config.io_timeout);

    ctx->set_handler_context(this, handler_ctx);
}

void h2o_fastcgi_handler_t::on_context_dispose(h2o_context_t *ctx) {
    auto handler_ctx = (fcgi_context_t *)ctx->get_handler_context(this);

    if (handler_ctx == NULL)
        return;

    h2o_timeout_t::dispose(ctx->loop, &handler_ctx->io_timeout);
    h2o_mem_free(handler_ctx);
}

void h2o_fastcgi_handler_t::dispose(h2o_base_handler_t *self) {
	auto handler = (h2o_fastcgi_handler_t *)self;
    if (handler->config.callbacks.dispose != NULL)
        handler->config.callbacks.dispose(handler, handler->config.callbacks.data);

    h2o_socketpool_dispose(&handler->sockpool);
    h2o_mem_free(handler->config.document_root.base);
    h2o_mem_free(handler);
}

static h2o_fastcgi_handler_t *register_common(h2o_pathconf_t *pathconf, h2o_fastcgi_config_vars_t *vars) {
    auto handler = pathconf->create_handler<h2o_fastcgi_handler_t>();

    handler->on_req = on_req;
    handler->config = *vars;
    if (vars->document_root.base != NULL)
        handler->config.document_root.strdup(vars->document_root);

    return handler;
}

h2o_fastcgi_handler_t *h2o_fastcgi_register_by_hostport(h2o_pathconf_t *pathconf,
        const char *host, uint16_t port,
        h2o_fastcgi_config_vars_t *vars) {
    h2o_fastcgi_handler_t *handler = register_common(pathconf, vars);

    h2o_socketpool_init_by_hostport(&handler->sockpool,
            h2o_iovec_t::create(host, strlen(host)), port, SIZE_MAX /* FIXME */);
    return handler;
}

h2o_fastcgi_handler_t *h2o_fastcgi_register_by_address(h2o_pathconf_t *pathconf,
        struct sockaddr *sa, socklen_t salen,
        h2o_fastcgi_config_vars_t *vars) {
    h2o_fastcgi_handler_t *handler = register_common(pathconf, vars);

    h2o_socketpool_init_by_address(&handler->sockpool, sa, salen, SIZE_MAX /* FIXME */);
    return handler;
}
