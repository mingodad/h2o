/*
 * Copyright (c) 2015-2016 DeNA Co., Ltd., Kazuho Oku
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
 extern "C" {
#include "h2o/httpparser.h"
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/string.h>
#include <mruby_input_stream.h>
}
#include "h2o/mruby_.h"

struct h2o_mruby_http_request_context_t {
    h2o_mruby_generator_t *generator;
    h2o_http1client_t *client;
    mrb_value receiver;
    struct {
        h2o_buffer_t *buf;
        h2o_iovec_t body; /* body.base != NULL indicates that post content exists (and the length MAY be zero) */
        int method_is_head : 1;
        int has_transfer_encoding : 1;
    } req;
    struct {
        h2o_buffer_t *after_closed; /* when client becomes NULL, rest of the data will be stored to this pointer */
        int has_content;
    } resp;
    struct {
        mrb_value request;
        mrb_value input_stream;
    } refs;
    void (*shortcut_notify_cb)(h2o_mruby_generator_t *generator);
};

static void on_gc_dispose_request(mrb_state *mrb, void *_ctx)
{
    auto ctx = (h2o_mruby_http_request_context_t *)_ctx;
    if (ctx != NULL)
        ctx->refs.request = mrb_nil_value();
}

const static struct mrb_data_type request_type =
    {"http_request", on_gc_dispose_request};

static void on_gc_dispose_input_stream(mrb_state *mrb, void *_ctx)
{
    auto ctx = (h2o_mruby_http_request_context_t *)_ctx;
    if (ctx != NULL)
        ctx->refs.input_stream = mrb_nil_value();
}

const static struct mrb_data_type input_stream_type =
    {"http_input_stream", on_gc_dispose_input_stream};

static mrb_value create_downstream_closed_exception(mrb_state *mrb)
{
    return mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "downstream HTTP closed");
}

static mrb_value detach_receiver(h2o_mruby_http_request_context_t *ctx)
{
    mrb_value ret = ctx->receiver;
    assert(!mrb_nil_p(ret));
    ctx->receiver = mrb_nil_value();
    return ret;
}

static void on_dispose(void *_ctx)
{
    auto ctx = (h2o_mruby_http_request_context_t *)_ctx;

    /* clear the refs */
    if (ctx->client != NULL) {
        ctx->client->cancel();
        ctx->client = NULL;
    }
    if (!mrb_nil_p(ctx->refs.request))
        DATA_PTR(ctx->refs.request) = NULL;
    if (!mrb_nil_p(ctx->refs.input_stream))
        DATA_PTR(ctx->refs.input_stream) = NULL;

    /* clear bufs */
    h2o_buffer_dispose(&ctx->req.buf);
    h2o_buffer_dispose(&ctx->resp.after_closed);

    /* notify the app, if it is waiting to hear from us */
    if (!mrb_nil_p(ctx->receiver)) {
        mrb_state *mrb = ctx->generator->ctx->mrb;
        int gc_arena = mrb_gc_arena_save(mrb);
        ctx->generator->run_fiber(detach_receiver(ctx),
                create_downstream_closed_exception(mrb), NULL);
        mrb_gc_arena_restore(mrb, gc_arena);
    }
}

static void post_response(h2o_mruby_http_request_context_t *ctx,
        int status, const phr_header *headers_sorted,
                          size_t num_headers)
{
    mrb_state *mrb = ctx->generator->ctx->mrb;
    int gc_arena = mrb_gc_arena_save(mrb);
    size_t i;
    //auto hs = ((const h2o_headers_t*)headers_sorted)->entries;

    mrb_value resp = mrb_ary_new_capa(mrb, 3);

    /* set status */
    mrb_ary_set(mrb, resp, 0, mrb_fixnum_value(status));

    /* set headers */
    mrb_value headers_hash = mrb_hash_new_capa(mrb, (int)num_headers);
    for (i = 0; i < num_headers; ++i) {
        /* skip the headers, we determine the eos! */
        if (h2o_phr_header_name_is_literal(headers_sorted[i], "content-length") ||
            h2o_phr_header_name_is_literal(headers_sorted[i], "transfer-encoding"))
            continue;
        /* build and set the hash entry */
        mrb_value k = mrb_str_new(mrb, headers_sorted[i].name, headers_sorted[i].name_len);
        mrb_value v = mrb_str_new(mrb, headers_sorted[i].value, headers_sorted[i].value_len);
        while (i + 1 < num_headers && h2o_phr_header_name_cmp(headers_sorted[i], headers_sorted[i + 1])) {
            ++i;
            v = mrb_str_cat_lit(mrb, v, "\n");
            v = mrb_str_cat(mrb, v, headers_sorted[i].value, headers_sorted[i].value_len);
        }
        mrb_hash_set(mrb, headers_hash, k, v);
    }
    mrb_ary_set(mrb, resp, 1, headers_hash);

    /* set input stream */
    assert(mrb_nil_p(ctx->refs.input_stream));
    ctx->refs.input_stream = h2o_mruby_create_data_instance(
        mrb, mrb_ary_entry(ctx->generator->ctx->constants,
        H2O_MRUBY_HTTP_INPUT_STREAM_CLASS), ctx, &input_stream_type);
    mrb_ary_set(mrb, resp, 2, ctx->refs.input_stream);

    if (mrb_nil_p(ctx->receiver)) {
        /* is async */
        mrb_funcall(mrb, ctx->refs.request, "_set_response", 1, resp);
        if (mrb->exc != NULL) {
            fprintf(stderr, "_set_response failed\n");
            abort();
        }
    } else {
        /* send response to the waiting receiver */
        ctx->generator->run_fiber(detach_receiver(ctx), resp, NULL);
    }

    mrb_gc_arena_restore(mrb, gc_arena);
}

static void post_error(h2o_mruby_http_request_context_t *ctx,
        const char *errstr)
{
    static const phr_header headers_sorted[] =
        {{H2O_STRLIT("content-type"), H2O_STRLIT("text/plain; charset=utf-8")}};

    ctx->client = NULL;
    size_t errstr_len = strlen(errstr);
    h2o_buffer_append(&ctx->resp.after_closed, errstr, errstr_len);
    ctx->resp.has_content = 1;

    post_response(ctx, 500, headers_sorted, sizeof(headers_sorted) / sizeof(headers_sorted[0]));
}

static mrb_value build_chunk(h2o_mruby_http_request_context_t *ctx)
{
    mrb_value chunk;

    assert(ctx->resp.has_content);
    #define new_str_from(mx, b) mrb_str_new(mx->generator->ctx->mrb, mx->b->bytes, mx->b->size)

    if (ctx->client != NULL) {
        assert(ctx->client->sock->input->size != 0);
        chunk = new_str_from(ctx, client->sock->input);
        h2o_buffer_consume_all(&ctx->client->sock->input);
        ctx->resp.has_content = 0;
    } else {
        if (ctx->resp.after_closed->size == 0) {
            chunk = mrb_nil_value();
        } else {
            chunk = new_str_from(ctx, resp.after_closed);
            h2o_buffer_consume_all(&ctx->resp.after_closed);
        }
        /* has_content is retained as true, so that repeated calls will return nil immediately */
    }
    #undef new_str_from

    return chunk;
}

static int on_body(h2o_http1client_t *client, const char *errstr)
{
    auto ctx = (h2o_mruby_http_request_context_t *)client->data;

    if (errstr != NULL) {
        h2o_buffer_t *tmp = ctx->resp.after_closed;
        ctx->resp.after_closed = client->sock->input;
        client->sock->input = tmp;
        ctx->client = NULL;
        ctx->resp.has_content = 1;
    } else if (client->sock->input->size != 0) {
        ctx->resp.has_content = 1;
    }

    if (ctx->resp.has_content) {
        if (ctx->shortcut_notify_cb != NULL) {
            ctx->shortcut_notify_cb(ctx->generator);
        } else if (!mrb_nil_p(ctx->receiver)) {
            int gc_arena = mrb_gc_arena_save(ctx->generator->ctx->mrb);
            mrb_value chunk = build_chunk(ctx);
            ctx->generator->run_fiber(detach_receiver(ctx), chunk, NULL);
            mrb_gc_arena_restore(ctx->generator->ctx->mrb, gc_arena);
        }
    }
    return 0;
}

static int headers_sort_cb(const void *_x, const void *_y)
{
    auto x = (const struct phr_header *)_x, y = (const struct phr_header *)_y;

    if (x->name_len < y->name_len)
        return -1;
    if (x->name_len > y->name_len)
        return 1;
    return memcmp(x->name, y->name, x->name_len);
}

static h2o_http1client_body_cb on_head(h2o_http1client_t *client,
        const char *errstr, int minor_version, int status,
        h2o_iovec_t msg, phr_header *headers, size_t num_headers)
{
    auto ctx = (h2o_mruby_http_request_context_t *)client->data;

    if (errstr != NULL) {
        if (errstr != h2o_http1client_error_is_eos) {
            /* error */
            post_error(ctx, errstr);
            return NULL;
        }
        /* closed without body */
        ctx->client = NULL;
    }

    qsort(headers, num_headers, sizeof(headers[0]), headers_sort_cb);
    post_response(ctx, status, headers, num_headers);
    return on_body;
}

static h2o_http1client_head_cb on_connect(h2o_http1client_t *client,
        const char *errstr, h2o_iovec_t **reqbufs, size_t *reqbufcnt,
                                          int *method_is_head)
{
    auto ctx = (h2o_mruby_http_request_context_t *)client->data;

    if (errstr != NULL) {
        post_error(ctx, errstr);
        return NULL;
    }

    *reqbufs = ctx->generator->req->pool.alloc_for<h2o_iovec_t>(2);
    (**reqbufs).init(ctx->req.buf->bytes, ctx->req.buf->size);
    *reqbufcnt = 1;
    if (ctx->req.body.base != NULL)
        (*reqbufs)[(*reqbufcnt)++] = ctx->req.body;
    *method_is_head = ctx->req.method_is_head;
    return on_head;
}

static int flatten_request_header(h2o_mruby_context_t *handler_ctx,
        h2o_iovec_t name, h2o_iovec_t value, void *_ctx)
{
    auto ctx = (h2o_mruby_http_request_context_t *)_ctx;

    /* ignore certain headers */
    if (h2o_io_vector_literal_lcis(name, "content-length") ||
        h2o_io_vector_literal_lcis(name, "connection") ||
            h2o_io_vector_literal_lcis(name, "host"))
        return 0;

    /* mark the existence of transfer-encoding in order to prevent us from adding content-length header */
    if (h2o_io_vector_literal_lcis(name, "transfer-encoding"))
        ctx->req.has_transfer_encoding = 1;

    h2o_buffer_reserve(&ctx->req.buf, name.len + value.len + sizeof(": \r\n") - 1);
    h2o_buffer_append(&ctx->req.buf, name.base, name.len);
    h2o_buffer_append(&ctx->req.buf, H2O_STRLIT(": "));
    h2o_buffer_append(&ctx->req.buf, value.base, value.len);
    h2o_buffer_append(&ctx->req.buf, H2O_STRLIT("\r\n"));

    return 0;
}

static mrb_value http_request_method(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_generator_t *generator;
    const char *arg_url;
    mrb_int arg_url_len;
    mrb_value arg_hash;
    h2o_iovec_t method;
    h2o_url_t url;

    /* parse args */
    arg_hash = mrb_nil_value();
    mrb_get_args(mrb, "s|H", &arg_url, &arg_url_len, &arg_hash);

    /* precond check */
    if ((generator = h2o_mruby_current_generator) == NULL || generator->req == NULL)
        mrb_exc_raise(mrb, create_downstream_closed_exception(mrb));

    /* allocate context and initialize */
    auto ctx = generator->req->pool.alloc_shared_for<h2o_mruby_http_request_context_t>(1, on_dispose);
    h2o_clearmem(ctx);
    ctx->generator = generator;
    ctx->receiver = mrb_nil_value();
    h2o_buffer_init(&ctx->req.buf, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&ctx->resp.after_closed, &h2o_socket_buffer_prototype);
    ctx->refs.request = mrb_nil_value();
    ctx->refs.input_stream = mrb_nil_value();

    /* uri */
    if (url.parse(arg_url, arg_url_len) != 0)
        mrb_raise(mrb, E_ARGUMENT_ERROR, "invaild URL");

    /* method */
    method.init(H2O_STRLIT("GET"));
    if (mrb_hash_p(arg_hash)) {
        mrb_value t = mrb_hash_get(mrb, arg_hash, mrb_symbol_value(generator->ctx->symbols.sym_method));
        if (!mrb_nil_p(t)) {
            t = mrb_str_to_str(mrb, t);
            method.init(RSTRING_PTR(t), RSTRING_LEN(t));
        }
    }

    /* start building the request */
    h2o_buffer_reserve(&ctx->req.buf, method.len + 1);
    h2o_buffer_append(&ctx->req.buf, method.base, method.len);
    h2o_buffer_append(&ctx->req.buf, H2O_STRLIT(" "));
    h2o_buffer_reserve(&ctx->req.buf,
                       url.path.len + url.authority.len + sizeof(" HTTP/1.1\r\nConnection: close\r\nHost: \r\n") - 1);
    h2o_buffer_append(&ctx->req.buf, url.path.base, url.path.len);
    h2o_buffer_append(&ctx->req.buf, H2O_STRLIT(" HTTP/1.1\r\nConnection: close\r\nHost: "));
    h2o_buffer_append(&ctx->req.buf, url.authority.base, url.authority.len);
    h2o_buffer_append(&ctx->req.buf, H2O_STRLIT("\r\n"));

    /* headers */
    if (mrb_hash_p(arg_hash)) {
        mrb_value headers = mrb_hash_get(mrb, arg_hash, mrb_symbol_value(generator->ctx->symbols.sym_headers));
        if (!mrb_nil_p(headers)) {
            if (generator->ctx->iterate_headers(headers, flatten_request_header, ctx) != 0) {
                mrb_value exc = mrb_obj_value(mrb->exc);
                mrb->exc = NULL;
                mrb_exc_raise(mrb, exc);
            }
        }
    }
    /* body */
    if (mrb_hash_p(arg_hash)) {
        mrb_value body = mrb_hash_get(mrb, arg_hash, mrb_symbol_value(generator->ctx->symbols.sym_body));
        if (!mrb_nil_p(body)) {
            if (mrb_obj_eq(mrb, body, generator->rack_input)) {
                /* fast path */
                mrb_int pos;
                mrb_input_stream_get_data(mrb, body, NULL, NULL, &pos, NULL, NULL);
                ctx->req.body = generator->req->entity;
                ctx->req.body.base += pos;
                ctx->req.body.len -= pos;
            } else {
                if (!mrb_string_p(body)) {
                    body = mrb_funcall(mrb, body, "read", 0);
                    if (!mrb_string_p(body))
                        mrb_raise(mrb, E_ARGUMENT_ERROR, "body.read did not return string");
                }
                ctx->req.body.strdup(&ctx->generator->req->pool, RSTRING_PTR(body), RSTRING_LEN(body));
            }
            if (!ctx->req.has_transfer_encoding) {
                char buf[64];
                size_t l = (size_t)snprintf(buf, sizeof(buf), "content-length: %zu\r\n", ctx->req.body.len);
                h2o_buffer_reserve(&ctx->req.buf, l);
                h2o_buffer_append(&ctx->req.buf, buf, l);
            }
        }
    }

    h2o_buffer_reserve(&ctx->req.buf, 2);
    h2o_buffer_append(&ctx->req.buf, H2O_STRLIT("\r\n"));

    /* build request and connect */
    h2o_http1client_t::connect(&ctx->client, ctx,
        &generator->req->conn->ctx->proxy.client_ctx, url.host,
        url.get_port(), on_connect);

    ctx->refs.request = h2o_mruby_create_data_instance(mrb,
        mrb_ary_entry(generator->ctx->constants, H2O_MRUBY_HTTP_REQUEST_CLASS),
                                                       ctx, &request_type);
    return ctx->refs.request;
}

mrb_value h2o_mruby_generator_t::http_join_response_callback(
    mrb_value receiver, mrb_value args, int *next_action)
{
    mrb_state *mrb = this->ctx->mrb;

    if (this->req == NULL)
        return create_downstream_closed_exception(mrb);

    auto ctx = (h2o_mruby_http_request_context_t*)
        mrb_data_check_get_ptr(mrb, mrb_ary_entry(args, 0), &request_type);
    if (ctx == NULL)
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "HttpRequest#join wrong self");

    ctx->receiver = receiver;
    *next_action = H2O_MRUBY_CALLBACK_NEXT_ACTION_ASYNC;
    return mrb_nil_value();
}

mrb_value h2o_mruby_generator_t::http_fetch_chunk_callback(
        mrb_value receiver, mrb_value args, int *next_action)
{
    mrb_state *mrb = this->ctx->mrb;
    mrb_value ret;

    if (this->req == NULL)
        return create_downstream_closed_exception(mrb);

    auto ctx = (h2o_mruby_http_request_context_t*)
        mrb_data_check_get_ptr(mrb, mrb_ary_entry(args, 0), &input_stream_type);
    if (ctx == NULL)
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "_HttpInputStream#each wrong self");

    if (ctx->resp.has_content) {
        ret = build_chunk(ctx);
    } else {
        ctx->receiver = receiver;
        *next_action = H2O_MRUBY_CALLBACK_NEXT_ACTION_ASYNC;
        ret = mrb_nil_value();
    }

    return ret;
}

h2o_mruby_http_request_context_t *h2o_mruby_http_set_shortcut(mrb_state *mrb,
        mrb_value obj, void (*cb)(h2o_mruby_generator_t *))
{
    auto ctx = (h2o_mruby_http_request_context_t *)mrb_data_check_get_ptr(mrb, obj, &input_stream_type);

    if (ctx == NULL)
        return NULL;
    ctx->shortcut_notify_cb = cb;
    return ctx;
}

h2o_buffer_t **h2o_mruby_http_peek_content(h2o_mruby_http_request_context_t *ctx,
        int *is_final)
{
    *is_final = ctx->client == NULL;
    return ctx->client != NULL && ctx->resp.has_content
            ? &ctx->client->sock->input : &ctx->resp.after_closed;
}

void h2o_mruby_http_request_init_context(h2o_mruby_context_t *ctx)
{
    mrb_state *mrb = ctx->mrb;
    struct RClass *module, *klass;

    mrb_define_method(mrb, mrb->kernel_module, "http_request",
        http_request_method, MRB_ARGS_ARG(1, 2));

    module = mrb_define_module(mrb, "H2O");
    klass = mrb_define_class_under(mrb, module, "HttpRequest", mrb->object_class);
    mrb_ary_set(mrb, ctx->constants, H2O_MRUBY_HTTP_REQUEST_CLASS, mrb_obj_value(klass));

    klass = mrb_define_class_under(mrb, module, "HttpInputStream", mrb->object_class);
    mrb_ary_set(mrb, ctx->constants, H2O_MRUBY_HTTP_INPUT_STREAM_CLASS, mrb_obj_value(klass));

    h2o_mruby_define_callback(mrb, "_h2o__http_join_response", H2O_MRUBY_CALLBACK_ID_HTTP_JOIN_RESPONSE);
    h2o_mruby_define_callback(mrb, "_h2o__http_fetch_chunk", H2O_MRUBY_CALLBACK_ID_HTTP_FETCH_CHUNK);

    h2o_mruby_eval_expr(mrb, "module H2O\n"
                             "  class HttpRequest\n"
                             "    def join\n"
                             "      if !@resp\n"
                             "        @resp = _h2o__http_join_response(self)\n"
                             "      end\n"
                             "      @resp\n"
                             "    end\n"
                             "    def _set_response(resp)\n"
                             "      @resp = resp\n"
                             "    end\n"
                             "  end\n"
                             "  class HttpInputStream\n"
                             "    def each\n"
                             "      while c = _h2o__http_fetch_chunk(self)\n"
                             "        yield c\n"
                             "      end\n"
                             "    end\n"
                             "    def join\n"
                             "      s = \"\"\n"
                             "      each do |c|\n"
                             "        s << c\n"
                             "      end\n"
                             "      s\n"
                             "    end\n"
                             "  end\n"
                             "end");
    h2o_mruby_assert(mrb);
}
