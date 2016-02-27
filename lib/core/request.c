/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Tatsuhiro Tsujikawa
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
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"

#define INITIAL_INBUFSZ 8192

struct delegate_request_deferred_t {
    h2o_req_t *req;
    h2o_handler_t *current_handler;
    h2o_timeout_entry_t _timeout;
};

struct reprocess_request_deferred_t {
    h2o_req_t *req;
    h2o_iovec_t method;
    const h2o_url_scheme_t *scheme;
    h2o_iovec_t authority;
    h2o_iovec_t path;
    h2o_req_overrides_t *overrides;
    int is_delegated;
    h2o_timeout_entry_t _timeout;
};

struct send_error_deferred_t {
    h2o_req_t *req;
    int status;
    const char *reason;
    const char *body;
    int flags;
    h2o_timeout_entry_t _timeout;
};

//static h2o_hostconf_t *find_hostconf(h2o_hostconf_t **hostconfs, h2o_iovec_t authority, uint16_t default_port)
static h2o_hostconf_t *find_hostconf(h2o_req_t *req, bool onInput=false)
{
    h2o_iovec_t hostname;
    uint16_t port;
    char *hostname_lc;
    h2o_hostconf_t *result = NULL;
    h2o_hostconf_t **hostconfs = req->conn->hosts;
    h2o_iovec_t &authority = onInput ? req->input.authority : req->authority;
    uint16_t default_port = onInput ? req->input.scheme->default_port : req->scheme->default_port;

    /* safe-guard for alloca */
    if (authority.len >= 65536)
        return NULL;

    /* extract the specified hostname and port */
    if (h2o_url_parse_hostport(authority.base, authority.len, &hostname, &port) == NULL)
        return NULL;
    if (port == H2O_PORT_NOT_SET)
        port = default_port;

    /* convert supplied hostname to lower-case */
    hostname_lc = (char*)h2o_mem_alloca(hostname.len);
    memcpy(hostname_lc, hostname.base, hostname.len);
    h2o_strtolower_n(hostname_lc, hostname.len);

    do {
        h2o_hostconf_t *hostconf = *hostconfs;
        if (hostconf->authority.port == port || (hostconf->authority.port == H2O_PORT_NOT_SET && port == default_port)) {
            if (hostconf->authority.host.base[0] == '*') {
                /* matching against "*.foo.bar" */
                size_t cmplen = hostconf->authority.host.len - 1;
                if (cmplen < hostname.len &&
                    memcmp(hostconf->authority.host.base + 1, hostname_lc + hostname.len - cmplen, cmplen) == 0)
                    {
                        result = hostconf;
                        goto CleanAlloca;
                    }
            } else {
                /* exact match */
                if (hostconf->authority.host.isEq(hostname_lc, hostname.len))
                {
                    result = hostconf;
                    goto CleanAlloca;
                }
            }
        }
    } while (*++hostconfs != NULL);

CleanAlloca:
    h2o_mem_alloca_free(hostname_lc);
    return result;
}

static h2o_hostconf_t *setup_before_processing(h2o_req_t *req)
{
    //h2o_context_t *ctx = req->conn->ctx;
    h2o_hostconf_t *hostconf;

    req->set_processed_at();

    /* find the host context */
    if (req->input.authority.base != NULL) {
        if (req->conn->hosts[1] == NULL || (hostconf = find_hostconf(req, true)) == NULL)
            hostconf = *req->conn->hosts;
    } else {
        /* set the authority name to the default one */
        hostconf = *req->conn->hosts;
        req->input.authority = hostconf->authority.hostport;
    }

    req->scheme = req->input.scheme;
    req->method = req->input.method;
    req->authority = req->input.authority;
    req->path = req->input.path;
    req->path_normalized = h2o_url_normalize_path(&req->pool, req->input.path.base, req->input.path.len, &req->query_at);
    req->input.query_at = req->query_at; /* we can do this since input.path == path */

    return hostconf;
}

static void call_handlers(h2o_req_t *req, size_t handler_idx)
{
    auto &handlers = req->pathconf->handlers;
    for (; handler_idx < handlers.size; ++handler_idx)
    {
        auto the_handle = handlers[handler_idx];
        if (the_handle->on_req(the_handle, req) == 0)
            return;
    }

    req->send_error(404, "File Not Found", "not found", 0);
}

static void process_hosted_request(h2o_req_t *req, h2o_hostconf_t *hostconf)
{
    size_t i;

    req->hostconf = hostconf;
    req->pathconf = &hostconf->fallback_path;

    /* setup pathconf, or redirect to "path/" */
    for (i = 0; i != hostconf->paths.size; ++i) {
        h2o_pathconf_t *pathconf = hostconf->paths.entries + i;
        size_t confpath_wo_slash = pathconf->path.len - 1;
        if (req->path_normalized.len >= confpath_wo_slash &&
            memcmp(req->path_normalized.base, pathconf->path.base, confpath_wo_slash) == 0) {
            if (req->path_normalized.len == confpath_wo_slash) {
                req->pathconf = pathconf;
                h2o_iovec_t dest = h2o_uri_escape(&req->pool, pathconf->path.base, pathconf->path.len, "/");
                if (req->query_at != SIZE_MAX)
                {
                    h2o_concat(dest, &req->pool, dest, h2o_iovec_t::create(req->path.base + req->query_at, req->path.len - req->query_at));
                }
                req->send_redirect(301, "Moved Permanently", dest);
                return;
            }
            if (req->path_normalized.base[confpath_wo_slash] == '/') {
                req->pathconf = pathconf;
                break;
            }
        }
    }

    call_handlers(req, 0);
}

static void deferred_proceed_cb(h2o_timeout_entry_t *entry)
{
    auto req = (h2o_req_t*)entry->data;
    req->proceed_response();
}

static void close_generator_and_filters(h2o_req_t *req)
{
    /* close the generator if it is still open */
    auto &generator = req->_generator;
    if (generator != NULL) {
        /* close generator */
        if (generator->stop != NULL)
            generator->stop(generator, req);
        generator = NULL;
    }
    /* close the ostreams still open */
    for (auto &top = req->_ostr_top; top->next != NULL; top = top->next) {
        if (top->stop != NULL)
            top->stop(top, req);
    }
}

static void reset_response(h2o_req_t *req)
{
    req->res = {0, "OK", SIZE_MAX, {}};
    req->_next_filter_index = 0;
    req->bytes_sent = 0;
}

void h2o_req_t::init(h2o_req_t *req, h2o_conn_t *conn, h2o_req_t *src)
{
    /* clear all memory (expect memory pool, since it is large) */
    h2o_clearmem(req);

    /* init memory pool (before others, since it may be used) */
    req->pool.init();

    /* init properties that should be initialized to non-zero */
    req->conn = conn;
    req->_timeout_entry.cb = deferred_proceed_cb;
    req->_timeout_entry.data = req;
    req->res.reason = "OK"; /* default to "OK" regardless of the status value, it's not important after all (never sent in HTTP2) */
    req->res.content_length = SIZE_MAX;
    req->preferred_chunk_size = SIZE_MAX;

    if (src != NULL) {
#define COPY(buf) \
    { \
        req->buf.base = req->pool.alloc_for<char>(src->buf.len); \
        memcpy(req->buf.base, src->buf.base, src->buf.len); \
        req->buf.len = src->buf.len; \
    }
        COPY(input.authority);
        COPY(input.method);
        COPY(input.path);
        req->input.scheme = src->input.scheme;
        req->version = src->version;
        req->headers.assign(&req->pool, &src->headers);
        req->entity = src->entity;
        req->http1_is_persistent = src->http1_is_persistent;
        req->timestamps = src->timestamps;
        if (src->upgrade.base != NULL) {
            COPY(upgrade);
        } else {
            req->upgrade.base = NULL;
            req->upgrade.len = 0;
        }
#undef COPY
    }
}

void h2o_req_t::dispose(h2o_req_t *req)
{
    close_generator_and_filters(req);

    req->_timeout_entry.stop();

    if (req->version != 0 && req->pathconf != NULL) {
        auto &loggers = req->pathconf->loggers;
        for (size_t i=0; i != loggers.size; ++i) {
            auto logger = loggers[i];
            logger->log_access(logger, req);
        }
    }

    req->pool.clear();
}

void h2o_req_t::process()
{
    auto hostconf = setup_before_processing(this);
    process_hosted_request(this, hostconf);
}

void h2o_req_t::delegate_request(h2o_handler_t *current_handler)
{
    auto &handlers = this->pathconf->handlers;
    size_t handler_idx =0;
    for (; handler_idx != handlers.size; ++handler_idx)
    {
        if (handlers[handler_idx] == current_handler) {
            ++handler_idx;
            break;
        }
    }
    call_handlers(this, handler_idx);
}

static void on_delegate_request_cb(h2o_timeout_entry_t *entry)
{
    auto args = (delegate_request_deferred_t*)entry->data;
    args->req->delegate_request(args->current_handler);
}

void h2o_req_t::delegate_request_deferred(h2o_handler_t *current_handler)
{
    auto args = this->pool.alloc_for<delegate_request_deferred_t>();
    *args = {this, current_handler};
    args->_timeout.cb = on_delegate_request_cb;
    args->_timeout.data = args;
    this->conn->ctx->zero_timeout.start(this->conn->ctx->loop, &args->_timeout);
}

void h2o_req_t::reprocess_request(h2o_iovec_t method, const h2o_url_scheme_t *scheme, h2o_iovec_t authority,
                           h2o_iovec_t path, h2o_req_overrides_t *overrides, int is_delegated)
{
    h2o_hostconf_t *hostconf;

    /* close generators and filters that are already running */
    close_generator_and_filters(this);

    /* setup the request/response parameters */
    this->method = method;
    this->scheme = scheme;
    this->authority = authority;
    this->path = path;
    this->path_normalized = h2o_url_normalize_path(&this->pool, this->path.base, this->path.len, &this->query_at);
    this->overrides = overrides;
    this->res_is_delegated |= is_delegated;
    reset_response(this);

    /* check the delegation (or reprocess) counter */
    if (this->res_is_delegated) {
        if (this->num_delegated == this->conn->ctx->globalconf->max_delegations) {
            /* TODO log */
            this->send_error(502, "Gateway Error", "too many internal delegations", 0);
            return;
        }
        ++this->num_delegated;
    } else {
        if (this->num_reprocessed >= 5) {
            /* TODO log */
            this->send_error(502, "Gateway Error", "too many internal reprocesses", 0);
            return;
        }
        ++this->num_reprocessed;
    }

    /* handle the response using the handlers, if hostconf exists */
    if (this->overrides == NULL && (hostconf = find_hostconf(this)) != NULL) {
        process_hosted_request(this, hostconf);
        return;
    }
    /* uses the current pathconf, in other words, proxy uses the previous pathconf for building filters */
    h2o__proxy_process_request(this);
}

static void on_reprocess_request_cb(h2o_timeout_entry_t *entry)
{
    auto args = (reprocess_request_deferred_t*)entry->data;
    args->req->reprocess_request(args->method, args->scheme, args->authority, args->path, args->overrides, args->is_delegated);
}

void h2o_req_t::reprocess_request_deferred(h2o_iovec_t method, const h2o_url_scheme_t *scheme, h2o_iovec_t authority,
                                    h2o_iovec_t path, h2o_req_overrides_t *overrides, int is_delegated)
{
    auto args = this->pool.alloc_for<reprocess_request_deferred_t>();
    *args = {this, method, scheme, authority, path, overrides, is_delegated};
    args->_timeout.cb = on_reprocess_request_cb;
    args->_timeout.data = args;
    this->conn->ctx->zero_timeout.start(this->conn->ctx->loop, &args->_timeout);
}

void h2o_req_t::start_response(h2o_generator_t *generator)
{
    /* set generator */
    assert(this->_generator == NULL);
    this->_generator = generator;

    /* setup response filters */
    if (this->prefilters != NULL) {
        this->prefilters->on_setup_ostream(this->prefilters, this, &this->_ostr_top);
    } else {
        this->setup_next_ostream(&(this->_ostr_top));
    }
}

void h2o_req_t::send(h2o_iovec_t *bufs, size_t bufcnt, int is_final)
{
    size_t i;

    assert(this->_generator != NULL);

    if (is_final)
        this->_generator = NULL;

    for (i = 0; i != bufcnt; ++i)
        this->bytes_sent += bufs[i].len;

    this->_ostr_top->do_send(this->_ostr_top, this, bufs, bufcnt, is_final);
}

h2o_req_prefilter_t *h2o_req_t::add_prefilter(size_t sz)
{
    auto prefilter = (h2o_req_prefilter_t *)this->pool.alloc(sz);
    prefilter->next = this->prefilters;
    this->prefilters = prefilter;
    return prefilter;
}

h2o_ostream_t *h2o_req_t::add_ostream(size_t sz, h2o_ostream_t **slot)
{
    auto ostr = (h2o_ostream_t *)this->pool.alloc(sz);
    ostr->next = *slot;
    ostr->do_send = NULL;
    ostr->stop = NULL;
    ostr->start_pull = NULL;

    *slot = ostr;

    return ostr;
}

void h2o_req_t::send_next(h2o_ostream_t *ostream, h2o_iovec_t *bufs, size_t bufcnt, int is_final)
{
    if (is_final) {
        assert(this->_ostr_top == ostream);
        this->_ostr_top = ostream->next;
    } else if (bufcnt == 0) {
        this->conn->ctx->zero_timeout.start(this->conn->ctx->loop, &this->_timeout_entry);
        return;
    }
    ostream->next->do_send(ostream->next, this, bufs, bufcnt, is_final);
}

void h2o_req_t::fill_mime_attributes()
{
    ssize_t content_type_index;
    h2o_mimemap_type_t *mime;

    if (this->res.mime_attr != NULL)
        return;

    if ((content_type_index = this->res.headers.find(H2O_TOKEN_CONTENT_TYPE, -1)) != -1 &&
        (mime = h2o_mimemap_get_type_by_mimetype(this->pathconf->mimemap, this->res.headers[content_type_index].value, 0)) !=
            NULL)
        this->res.mime_attr = &mime->data.attr;
    else
        this->res.mime_attr = &h2o_mime_attributes_as_is;
}

void h2o_req_t::send_inline(const char *body, size_t len)
{
    static h2o_generator_t generator = {NULL, NULL};

    this->start_response(&generator);

    if (this->input.method.isEq("HEAD"))
    {
        this->send(NULL, 0, 1);
    }
    else
    {
        h2o_iovec_t buf = h2o_strdup(&this->pool, body, len);
        /* the function intentionally does not set the content length, since it may be used for generating 304 response, etc. */
        /* this->res.content_length = buf.len; */
        this->send(&buf, 1, 1);
    }
}

void h2o_req_t::send_error(int status, const char *reason, const char *body, int flags)
{
    if (this->pathconf == NULL) {
        auto hostconf = setup_before_processing(this);
        this->hostconf = hostconf;
        this->pathconf = &hostconf->fallback_path;
    }

    if ((flags & H2O_SEND_ERROR_HTTP1_CLOSE_CONNECTION) != 0)
        this->http1_is_persistent = 0;

    this->res.status = status;
    this->res.reason = reason;
    this->res.content_length = strlen(body);

    if ((flags & H2O_SEND_ERROR_KEEP_HEADERS) == 0)
        this->res.headers.reset();

    this->addResponseHeader(H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain; charset=utf-8"));

    this->send_inline(body, SIZE_MAX);
}

static void send_error_deferred_cb(h2o_timeout_entry_t *entry)
{
    auto args = (send_error_deferred_t*)entry->data;
    reset_response(args->req);
    args->req->send_error(args->status, args->reason, args->body, args->flags);
}

void h2o_req_t::send_error_deferred(int status, const char *reason, const char *body, int flags)
{
    auto args = this->pool.alloc_for<send_error_deferred_t>();
    *args = {this, status, reason, body, flags};
    args->_timeout.cb = send_error_deferred_cb;
    args->_timeout.data = args;
    this->conn->ctx->zero_timeout.start(this->conn->ctx->loop, &args->_timeout);
    h2o_mem_alloca_free(args);
}

void h2o_req_t::log_error(const char *module, const char *fmt, ...)
{
#define FMT_PATH_LEN 32
#define PREFIX "[%s] in request:%." #FMT_PATH_LEN "s:"
    size_t max_size = sizeof("[] in request::\n") + FMT_PATH_LEN + strlen(module) + strlen(fmt);
    char *fmt_prefixed = (char*)h2o_mem_alloca(max_size), *p = fmt_prefixed;

    p += snprintf(fmt_prefixed, max_size, "[%s] in request:", module);
    if (this->path.len < FMT_PATH_LEN) {
        memcpy(p, this->path.base, this->path.len);
        p += this->path.len;
    } else {
        const char ellipsis[] = "...";
        size_t ellipsis_len = sizeof(ellipsis)-1;
        int visible_len = FMT_PATH_LEN - ellipsis_len;
        memcpy(p, this->path.base, visible_len);
        p += visible_len;
        memcpy(p, ellipsis, ellipsis_len);
        p += ellipsis_len;
    }
    *p++ = ':';
    strcpy(p, fmt);
    strcat(p, "\n");

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt_prefixed, args);
    va_end(args);
#undef PREFIX
#undef FMT_PATH_LEN
}

void h2o_req_t::send_redirect(int status, const char *reason, const char *url, size_t url_len)
{
    if (this->res_is_delegated) {
        h2o_get_redirect_method(this->method, status);
        send_redirect_internal(this->method, url, url_len, 0);
        return;
    }

    static h2o_generator_t generator = {NULL, NULL};
    static const h2o_iovec_t body_prefix = {H2O_STRLIT("<!DOCTYPE html><TITLE>Moved</TITLE><P>The document has moved <A HREF=\"")};
    static const h2o_iovec_t body_suffix = {H2O_STRLIT("\">here</A>")};

    /* build and send response */
    h2o_iovec_t bufs[3];
    size_t bufcnt;
    if (this->input.method.isEq("HEAD")) {
        this->res.content_length = SIZE_MAX;
        bufcnt = 0;
    } else {
        bufs[0] = body_prefix;
        bufs[1] = h2o_htmlescape(&this->pool, url, url_len);
        bufs[2] = body_suffix;
        bufcnt = 3;
        this->res.content_length = body_prefix.len + bufs[1].len + body_suffix.len;
    }
    this->res.status = status;
    this->res.reason = reason;
    this->res.headers = {};
    this->addResponseHeader(H2O_TOKEN_LOCATION, url, url_len);
    this->addResponseHeader(H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/html; charset=utf-8"));
    this->start_response(&generator);
    this->send(bufs, bufcnt, 1);
}

void h2o_req_t::send_redirect_internal(h2o_iovec_t method, const char *url_str, size_t url_len, int preserve_overrides)
{
    h2o_url_t url;

    /* parse the location URL */
    if (url.parse_relative(url_str, url_len) != 0) {
        /* TODO log fprintf(stderr, "[proxy] cannot handle location header: %.*s\n", (int)url_len, url); */
        this->send_error_deferred(502, "Gateway Error", "internal error", 0);
        return;
    }
    /* convert the location to absolute (while creating copies of the values passed to the deferred call) */
    if (url.scheme == NULL)
        url.scheme = this->scheme;
    if (url.authority.base == NULL) {
        if (this->hostconf != NULL)
            url.authority = this->hostconf->authority.hostport;
        else
            url.authority = this->authority;
    } else {
        if (h2o_io_vector_lcis(url.authority, this->authority)) {
            url.authority = this->authority;
        } else {
            url.authority.strdup(&this->pool, url.authority);
            preserve_overrides = 0;
        }
    }
    h2o_iovec_t base_path = this->path;
    h2o_url_resolve_path(&base_path, &url.path);
    h2o_concat(url.path, &this->pool, base_path, url.path);

    this->reprocess_request_deferred(this->method, url.scheme, url.authority, url.path, preserve_overrides ? this->overrides: NULL, 1);
}

h2o_iovec_t h2o_get_redirect_method(h2o_iovec_t method, int status)
{
    if (method.isEq("POST") && !(status == 307 || status == 308))
        method.init(H2O_STRLIT("GET"));
    return method;
}

int h2o_req_t::puth_path_in_link_header(const char *value, size_t value_len)
{
    if (this->conn->callbacks->push_path == NULL || this->res_is_delegated)
        return -1;

    h2o_iovec_t path =
        h2o_extract_push_path_from_link_header(&this->pool, value, value_len, this->input.scheme, &this->input.authority, &this->path);
    if (path.base == NULL)
        return -1;

    this->conn->callbacks->push_path(this, path.base, path.len);
    return 0;
}

int h2o_get_address_info(h2o_socket_address &sa, h2o_conn_t *conn, h2o_get_address_info_cb cb)
{
    socklen_t sslen;
    if ((sslen = cb(conn, (sockaddr *)&sa.ss)) == 0)
        return -1;
    sa.remote_addr_len = (uint16_t)h2o_socket_getnumerichost((sockaddr *) &sa.ss, sslen, sa.remote_addr);
    sa.port = (uint16_t)h2o_socket_getport((sockaddr *) &sa.ss);

    return 0;
}

