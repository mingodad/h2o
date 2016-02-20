/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Ryosuke Matsumoto,
 *                         Masayoshi Takahashi
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
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
extern "C" {
#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/string.h>
#include <mruby/throw.h>
#include <mruby/variable.h>
#include <mruby_input_stream.h>
}
#include "h2o/mruby_.h"

#define STATUS_FALLTHRU 399
#define FALLTHRU_SET_PREFIX "x-fallthru-set-"

#define FREEZE_STRING(v) RSTR_SET_FROZEN_FLAG(mrb_str_ptr(v))

__thread h2o_mruby_generator_t *h2o_mruby_current_generator = NULL;

void h2o_mruby__assert_failed(mrb_state *mrb, const char *file, int line)
{
    mrb_value obj = mrb_funcall(mrb, mrb_obj_value(mrb->exc), "inspect", 0);
    struct RString *error = mrb_str_ptr(obj);
    fprintf(stderr, "unexpected ruby error at file: \"%s\", line %d: %s", file, line, error->as.heap.ptr);
    abort();
}

static void set_h2o_root(mrb_state *mrb)
{
    const char *root = getenv("H2O_ROOT");
    if (root == NULL)
        root = H2O_TO_STR(H2O_ROOT);
    mrb_gv_set(mrb, mrb_intern_lit(mrb, "$H2O_ROOT"), mrb_str_new(mrb, root, strlen(root)));
}

mrb_value h2o_mruby_to_str(mrb_state *mrb, mrb_value v)
{
    if (!mrb_string_p(v))
        H2O_MRUBY_EXEC_GUARD({ v = mrb_str_to_str(mrb, v); });
    return v;
}

mrb_value h2o_mruby_eval_expr(mrb_state *mrb, const char *expr)
{
    return mrb_funcall(mrb, mrb_top_self(mrb), "eval", 1, mrb_str_new_cstr(mrb, expr));
}

void h2o_mruby_define_callback(mrb_state *mrb, const char *name, int id)
{
    char buf[1024];

    snprintf(buf, sizeof(buf),
                 "module Kernel\n"
                 "  def %s(*args)\n"
                 "    ret = Fiber.yield([\n"
                 "      %d,\n"
                 "      _h2o_create_resumer(),\n"
                 "      args,\n"
                 "    ])\n"
                 "    if ret.kind_of? Exception\n"
                 "      raise ret\n"
                 "    end\n"
                 "    ret\n"
                 "  end\n"
                 "end",
            name, id);
    h2o_mruby_eval_expr(mrb, buf);

    if (mrb->exc != NULL) {
        fprintf(stderr, "failed to define mruby function: %s\n", name);
        h2o_mruby_assert(mrb);
    }
}

mrb_value h2o_mruby_create_data_instance(mrb_state *mrb, mrb_value class_obj, void *ptr, const mrb_data_type *type)
{
    auto klass = mrb_class_ptr(class_obj);
    auto data = mrb_data_object_alloc(mrb, klass, ptr, type);
    return mrb_obj_value(data);
}

mrb_value h2o_mruby_compile_code(mrb_state *mrb, h2o_scripting_config_vars_t *config, char *errbuf)
{
    mrbc_context *cxt;
    struct mrb_parser_state *parser;
    struct RProc *proc = NULL;
    mrb_value result = mrb_nil_value();

    set_h2o_root(mrb);

    /* parse */
    if ((cxt = mrbc_context_new(mrb)) == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_MRUBY_MODULE_NAME);
        abort();
    }
    if (config->path != NULL)
        mrbc_filename(mrb, cxt, config->path);
    cxt->capture_errors = 1;
    cxt->lineno = config->lineno;
    if ((parser = mrb_parse_nstring(mrb, config->source.base, (int)config->source.len, cxt)) == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_MRUBY_MODULE_NAME);
        abort();
    }
    /* return erro if errbuf is supplied, or abort */
    if (parser->nerr != 0) {
        if (errbuf == NULL) {
            fprintf(stderr, "%s: internal error (unexpected state)\n", H2O_MRUBY_MODULE_NAME);
            abort();
        }
        snprintf(errbuf, 256, "line %d:%s", parser->error_buffer[0].lineno, parser->error_buffer[0].message);
        strcat(errbuf, "\n\n");
        if (h2o_str_at_position(errbuf + strlen(errbuf), config->source.base, config->source.len,
                                parser->error_buffer[0].lineno - config->lineno + 1, parser->error_buffer[0].column) != 0) {
            /* remove trailing "\n\n" in case we failed to append the source code at the error location */
            errbuf[strlen(errbuf) - 2] = '\0';
        }
        goto Exit;
    }
    /* generate code */
    if ((proc = mrb_generate_code(mrb, parser)) == NULL) {
        fprintf(stderr, "%s: internal error (mrb_generate_code failed)\n", H2O_MRUBY_MODULE_NAME);
        abort();
    }

    result = mrb_run(mrb, proc, mrb_top_self(mrb));
    if (mrb->exc != NULL) {
        mrb_value obj = mrb_funcall(mrb, mrb_obj_value(mrb->exc), "inspect", 0);
        struct RString *error = mrb_str_ptr(obj);
        snprintf(errbuf, 256, "%s", error->as.heap.ptr);
        mrb->exc = 0;
        result = mrb_nil_value();
        goto Exit;
    } else if (mrb_nil_p(result)) {
        snprintf(errbuf, 256, "returned value is not callable");
        goto Exit;
    }

Exit:
    mrb_parser_free(parser);
    mrbc_context_free(mrb, cxt);
    return result;
}

static h2o_iovec_t convert_header_name_to_env(h2o_mem_pool_t *pool, const h2o_iovec_t &name)
{
#define KEY_PREFIX "HTTP_"
#define KEY_PREFIX_LEN (sizeof(KEY_PREFIX) - 1)

    h2o_iovec_t ret;

    ret.len = name.len + KEY_PREFIX_LEN;
    ret.base = pool->alloc_for<char>(ret.len);

    memcpy(ret.base, KEY_PREFIX, KEY_PREFIX_LEN);

    char *d = ret.base + KEY_PREFIX_LEN;
    for (size_t len=0; len != name.len; ++len)
        *d++ = name.base[len] == '-' ? '_' : h2o_toupper(name.base[len]);

    return ret;

#undef KEY_PREFIX
#undef KEY_PREFIX_LEN
}

static mrb_value build_constants(mrb_state *mrb, const char *server_name, size_t server_name_len)
{
    mrb_value ary = mrb_ary_new_capa(mrb, H2O_MRUBY_NUM_CONSTANTS);
    mrb_int i;

    int gc_arena = mrb_gc_arena_save(mrb);

    {
        h2o_mem_pool_t pool;
        pool.init();
        for (i = 0; i != H2O_MAX_TOKENS; ++i) {
            const h2o_token_t *token = h2o__tokens + i;
            mrb_value lit = mrb_nil_value();
            if (token == H2O_TOKEN_CONTENT_TYPE) {
                lit = mrb_str_new_lit(mrb, "CONTENT_TYPE");
            } else if (token->buf.len != 0) {
                h2o_iovec_t n = convert_header_name_to_env(&pool, token->buf);
                lit = mrb_str_new(mrb, n.base, n.len);
            }
            if (mrb_string_p(lit)) {
                FREEZE_STRING(lit);
                mrb_ary_set(mrb, ary, i, lit);
            }
        }
        //pool.clear(); called by the destructor
    }

#define SET_STRING(idx, value) \
    { \
        mrb_value lit = (value); \
        FREEZE_STRING(lit); \
        mrb_ary_set(mrb, ary, idx, lit); \
    }
#define SET_LITERAL(idx, str) SET_STRING(H2O_MRUBY_LIT_##idx, mrb_str_new_lit(mrb, str))
#define SET_LITERAL1(idx) SET_LITERAL(idx, #idx)

    SET_LITERAL1(REQUEST_METHOD);
    SET_LITERAL1(SCRIPT_NAME);
    SET_LITERAL1(PATH_INFO);
    SET_LITERAL1(QUERY_STRING);
    SET_LITERAL1(SERVER_NAME);
    SET_LITERAL1(SERVER_ADDR);
    SET_LITERAL1(SERVER_PORT);
    SET_LITERAL1(CONTENT_LENGTH);
    SET_LITERAL1(REMOTE_ADDR);
    SET_LITERAL1(REMOTE_PORT);
    SET_LITERAL1(REMOTE_USER);
    SET_LITERAL(RACK_URL_SCHEME, "rack.url_scheme");
    SET_LITERAL(RACK_MULTITHREAD, "rack.multithread");
    SET_LITERAL(RACK_MULTIPROCESS, "rack.multiprocess");
    SET_LITERAL(RACK_RUN_ONCE, "rack.run_once");
    SET_LITERAL(RACK_HIJACK_, "rack.hijack?");
    SET_LITERAL(RACK_INPUT, "rack.input");
    SET_LITERAL(RACK_ERRORS, "rack.errors");
    SET_LITERAL1(SERVER_SOFTWARE);
    SET_STRING(H2O_MRUBY_LIT_SERVER_SOFTWARE_VALUE, mrb_str_new(mrb, server_name, server_name_len));
    SET_LITERAL(SEPARATOR_COMMA, ", ");
    SET_LITERAL(SEPARATOR_SEMICOLON, "; ");

#undef SET_LITERAL
#undef SET_STRING

    mrb_ary_set(mrb, ary, H2O_MRUBY_PROC_EACH_TO_ARRAY, h2o_mruby_eval_expr(mrb,
            "Proc.new do |o|\n"
            "  a = []\n"
            "  o.each do |x|\n"
            "    a << x\n"
            "  end\n"
            "  a\n"
            "end"));
    h2o_mruby_assert(mrb);

    /* sends exception using H2O_MRUBY_CALLBACK_ID_EXCEPTION_RAISED */
    mrb_ary_set(mrb, ary, H2O_MRUBY_PROC_APP_TO_FIBER, h2o_mruby_eval_expr(mrb,
            "Proc.new do |app|\n"
            "  cached = nil\n"
            "  Proc.new do |req|\n"
            "    fiber = cached\n"
            "    cached = nil\n"
            "    if !fiber\n"
            "      fiber = Fiber.new do\n"
            "        self_fiber = Fiber.current\n"
            "        req = Fiber.yield\n"
            "        while 1\n"
            "          begin\n"
            "            while 1\n"
            "              resp = app.call(req)\n"
            "              cached = self_fiber\n"
            "              req = Fiber.yield(resp)\n"
            "            end\n"
            "          rescue => e\n"
            "            cached = self_fiber\n"
            "            req = Fiber.yield([-1, e])\n"
            "          end\n"
            "        end\n"
            "      end\n"
            "      fiber.resume\n"
            "    end\n"
            "    fiber.resume(req)\n"
            "  end\n"
            "end"));
    h2o_mruby_assert(mrb);

    h2o_mruby_eval_expr(mrb, "module Kernel\n"
                             "  def _h2o_create_resumer()\n"
                             "    me = Fiber.current\n"
                             "    Proc.new do |v|\n"
                             "      me.resume(v)\n"
                             "    end\n"
                             "  end\n"
                             "end");
    h2o_mruby_assert(mrb);

    mrb_gc_arena_restore(mrb, gc_arena);
    return ary;
}

void h2o_mruby_handler_t::on_context_init(h2o_context_t *ctx)
{
    auto handler_ctx = h2o_mem_alloc_for<h2o_mruby_context_t>();

    handler_ctx->handler = this;

    /* init mruby in every thread */
    if ((handler_ctx->mrb = mrb_open()) == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_MRUBY_MODULE_NAME);
        abort();
    }
    handler_ctx->constants = build_constants(handler_ctx->mrb,
            ctx->globalconf->server_name.base, ctx->globalconf->server_name.len);
    #define create_symbol(sym) handler_ctx->symbols.sym_##sym = mrb_intern_lit(handler_ctx->mrb, #sym);
    create_symbol(call);
    create_symbol(close);
    create_symbol(method);
    create_symbol(headers);
    create_symbol(body);
    create_symbol(async);
    #undef create_symbol

    h2o_mruby_send_chunked_init_context(handler_ctx);
    h2o_mruby_http_request_init_context(handler_ctx);

    /* compile code (must be done for each thread) */
    int arena = mrb_gc_arena_save(handler_ctx->mrb);
    mrb_value proc = h2o_mruby_compile_code(handler_ctx->mrb, &this->config, NULL);
    handler_ctx->proc = mrb_funcall_argv(handler_ctx->mrb,
            mrb_ary_entry(handler_ctx->constants, H2O_MRUBY_PROC_APP_TO_FIBER),
            handler_ctx->symbols.sym_call, 1, &proc);
    h2o_mruby_assert(handler_ctx->mrb);
    mrb_gc_arena_restore(handler_ctx->mrb, arena);
    mrb_gc_protect(handler_ctx->mrb, handler_ctx->proc);

    ctx->set_handler_context(this, handler_ctx);
}

void h2o_mruby_handler_t::on_context_dispose(h2o_context_t *ctx)
{
    auto handler_ctx = (h2o_mruby_context_t*)ctx->get_handler_context(this);

    if (handler_ctx == NULL)
        return;

    mrb_close(handler_ctx->mrb);
    h2o_mem_free(handler_ctx);
}

void h2o_mruby_handler_t::dispose(h2o_base_handler_t *_handler)
{
    auto handler = (h2o_mruby_handler_t *)_handler;

    h2o_mem_free(handler->config.source.base);
    h2o_mem_free(handler->config.path);
    h2o_mem_free(handler);
}

static void report_exception(h2o_req_t *req, mrb_state *mrb)
{
    mrb_value obj = mrb_funcall(mrb, mrb_obj_value(mrb->exc), "inspect", 0);
    struct RString *error = mrb_str_ptr(obj);
    req->log_error(H2O_MRUBY_MODULE_NAME, "mruby raised: %s\n", error->as.heap.ptr);
    mrb->exc = NULL;
}

static void stringify_address(h2o_conn_t *conn,
        socklen_t (*cb)(h2o_conn_t *conn, struct sockaddr *), mrb_state *mrb,
        mrb_value *host, mrb_value *port)
{
    struct sockaddr_storage ss;
    socklen_t sslen;
    char buf[NI_MAXHOST];

    *host = mrb_nil_value();
    *port = mrb_nil_value();

    if ((sslen = cb(conn, (sockaddr *)&ss)) == 0)
        return;
    size_t l = h2o_socket_getnumerichost((sockaddr *)&ss, sslen, buf);
    if (l != SIZE_MAX)
        *host = mrb_str_new(mrb, buf, l);
    int32_t p = h2o_socket_getport((sockaddr *)&ss);
    if (p != -1) {
        l = (int)sprintf(buf, "%" PRIu16, (uint16_t)p);
        *port = mrb_str_new(mrb, buf, l);
    }
}

static void on_rack_input_free(mrb_state *mrb, const char *base, mrb_int len, void *_input_stream)
{
    /* reset ref to input_stream */
    auto input_stream = (mrb_value *)_input_stream;
    *input_stream = mrb_nil_value();
}

int build_env_sort_header_cb(const void *_x, const void *_y)
{
    auto x = (const h2o_header_t *)_x, y = (const h2o_header_t *)_y;
    if (x->name->len < y->name->len)
        return -1;
    if (x->name->len > y->name->len)
        return 1;
    if (x->name->base == y->name->base)
        return 0;
    return memcmp(x->name->base, y->name->base, x->name->len);
}

static mrb_value build_env(h2o_mruby_generator_t *generator)
{
    mrb_state *mrb = generator->ctx->mrb;
    mrb_value env = mrb_hash_new_capa(mrb, 16);
    #define set_env_mrb_str(key, str) mrb_hash_set(mrb, env, mrb_ary_entry(generator->ctx->constants, key), str)
    #define set_env_mrb_str_size(key, value, size) set_env_mrb_str(key, mrb_str_new(mrb, value.base, size))
    #define set_env_mrb_str_new(key, value) set_env_mrb_str_size(key, value, value.len)
    #define set_env_mrb_bool(key, bval) set_env_mrb_str(key, mrb_##bval##_value())


    /* environment */
    set_env_mrb_str_new(H2O_MRUBY_LIT_REQUEST_METHOD, generator->req->method);
    size_t confpath_len_wo_slash = generator->req->pathconf->path.len - 1;
    set_env_mrb_str_size(H2O_MRUBY_LIT_SCRIPT_NAME, generator->req->pathconf->path, confpath_len_wo_slash);
    set_env_mrb_str(H2O_MRUBY_LIT_PATH_INFO,
                 mrb_str_new(mrb, generator->req->path_normalized.base + confpath_len_wo_slash,
                             generator->req->path_normalized.len - confpath_len_wo_slash));
    set_env_mrb_str(H2O_MRUBY_LIT_QUERY_STRING,
                 generator->req->query_at != SIZE_MAX ? mrb_str_new(
                                                mrb, generator->req->path.base + generator->req->query_at + 1,
                                                generator->req->path.len - (generator->req->query_at + 1))
                                                : mrb_str_new_lit(mrb, ""));
    set_env_mrb_str_new(H2O_MRUBY_LIT_SERVER_NAME, generator->req->hostconf->authority.host);
    {
        mrb_value h, p;
        stringify_address(generator->req->conn, generator->req->conn->callbacks->get_sockname, mrb, &h, &p);
        if (!mrb_nil_p(h))
            set_env_mrb_str(H2O_MRUBY_LIT_SERVER_ADDR, h);
        if (!mrb_nil_p(p))
            set_env_mrb_str(H2O_MRUBY_LIT_SERVER_PORT, p);
    }
    set_env_mrb_str_new(H2O_TOKEN_HOST - h2o__tokens, generator->req->authority);
    if (generator->req->entity.base != NULL) {
        char buf[32];
        int l = sprintf(buf, "%zu", generator->req->entity.len);
        set_env_mrb_str(H2O_MRUBY_LIT_CONTENT_LENGTH, mrb_str_new(mrb, buf, l));
        generator->rack_input = mrb_input_stream_value(mrb, NULL, 0);
        mrb_input_stream_set_data(mrb, generator->rack_input, generator->req->entity.base,
                                  (mrb_int)generator->req->entity.len, 0,
                                  on_rack_input_free, &generator->rack_input);
        set_env_mrb_str(H2O_MRUBY_LIT_RACK_INPUT, generator->rack_input);
    }
    {
        mrb_value h, p;
        stringify_address(generator->req->conn, generator->req->conn->callbacks->get_peername, mrb, &h, &p);
        if (!mrb_nil_p(h))
            set_env_mrb_str(H2O_MRUBY_LIT_REMOTE_ADDR, h);
        if (!mrb_nil_p(p))
            set_env_mrb_str(H2O_MRUBY_LIT_REMOTE_PORT, p);
    }
    if (generator->req->remote_user.base != NULL)
        set_env_mrb_str_new(H2O_MRUBY_LIT_REMOTE_USER, generator->req->remote_user);

    { /* headers */
        size_t i = sizeof(h2o_header_t) * generator->req->headers.size;
        auto headers_sorted = (h2o_header_t *)h2o_mem_alloca(i);
        memcpy(headers_sorted, generator->req->headers.entries, i);
        qsort(headers_sorted, generator->req->headers.size, sizeof(*headers_sorted), build_env_sort_header_cb);
        for (i = 0; i != generator->req->headers.size; ++i) {
            const h2o_header_t *header = headers_sorted + i;
            mrb_value n, v;
            if (h2o_iovec_is_token(header->name)) {
                auto token = H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, header->name);
                if (token == H2O_TOKEN_TRANSFER_ENCODING)
                    continue;
                n = mrb_ary_entry(generator->ctx->constants, (mrb_int)(token - h2o__tokens));
            } else {
                h2o_iovec_t vec = convert_header_name_to_env(&generator->req->pool, *header->name);
                n = mrb_str_new(mrb, vec.base, vec.len);
            }
            v = mrb_str_new(mrb, header->value.base, header->value.len);
            while (i < generator->req->headers.size - 1) {
                if (!headers_sorted[i + 1].name->isEq(header->name))
                    break;
                header = headers_sorted + ++i;
                v = mrb_str_append(mrb, v, mrb_ary_entry(
                        generator->ctx->constants, header->name == &H2O_TOKEN_COOKIE->buf
                        ? H2O_MRUBY_LIT_SEPARATOR_SEMICOLON
                        : H2O_MRUBY_LIT_SEPARATOR_COMMA));
                v = mrb_str_append(mrb, v, mrb_str_new(mrb, header->value.base, header->value.len));
            }
            mrb_hash_set(mrb, env, n, v);
        }
        h2o_mem_alloca_free(headers_sorted);
    }

    /* rack.* */
    /* TBD rack.version? */
    set_env_mrb_str_new(H2O_MRUBY_LIT_RACK_URL_SCHEME, generator->req->scheme->name);
    /* we are using shared-none architecture, and therefore declare ourselves as multiprocess */
    set_env_mrb_bool(H2O_MRUBY_LIT_RACK_MULTITHREAD, false);
    set_env_mrb_bool(H2O_MRUBY_LIT_RACK_MULTIPROCESS, true);
    set_env_mrb_bool(H2O_MRUBY_LIT_RACK_RUN_ONCE, false);
    set_env_mrb_bool(H2O_MRUBY_LIT_RACK_HIJACK_, false);
    set_env_mrb_str(H2O_MRUBY_LIT_RACK_ERRORS, mrb_gv_get(mrb, mrb_intern_lit(mrb, "$stderr")));

    /* server name */
    set_env_mrb_str(H2O_MRUBY_LIT_SERVER_SOFTWARE,
                 mrb_ary_entry(generator->ctx->constants, H2O_MRUBY_LIT_SERVER_SOFTWARE_VALUE));

    return env;
}

static int handle_response_header(h2o_mruby_context_t *handler_ctx, h2o_iovec_t name, h2o_iovec_t value, void *_req)
{
    auto req = (h2o_req_t *)_req;
    const h2o_token_t *token;
    static const h2o_iovec_t fallthru_set_prefix = {H2O_STRLIT(FALLTHRU_SET_PREFIX)};

    /* convert name to lowercase */
    name.strdup(&req->pool, name);
    h2o_strtolower(name);

    if ((token = h2o_lookup_token(name.base, name.len)) != NULL) {
        if (token->proxy_should_drop) {
            /* skip */
        } else if (token == H2O_TOKEN_CONTENT_LENGTH) {
            req->res.content_length = h2o_strtosize(value.base, value.len);
        } else if (token == H2O_TOKEN_LINK && req->puth_path_in_link_header(value.base, value.len)) {
            /* do not send the link header that is going to be pushed */
        } else {
            value.strdup(&req->pool, value);
            req->addResponseHeader(token, value);
        }
    } else if (name.len > fallthru_set_prefix.len &&
               h2o_memis(name.base, fallthru_set_prefix.len, fallthru_set_prefix.base, fallthru_set_prefix.len)) {
        /* register additional request header if status is fallthru, otherwise discard */
        if (req->res.status == STATUS_FALLTHRU) {
            if (h2o_memis(name.base + fallthru_set_prefix.len, name.len - fallthru_set_prefix.len, H2O_STRLIT("remote-user")))
                req->remote_user.strdup(&req->pool, value);
        }
    } else {
        value.strdup(&req->pool, value);
        req->res.headers.add(&req->pool, name.base, name.len, 0, value.base, value.len);
    }

    return 0;
}

static void clear_rack_input(h2o_mruby_generator_t *generator)
{
    if (!mrb_nil_p(generator->rack_input))
        mrb_input_stream_set_data(generator->ctx->mrb, generator->rack_input, NULL, -1, 0, NULL, NULL);
}

static void on_generator_dispose(void *_generator)
{
    auto generator = (h2o_mruby_generator_t *)_generator;

    clear_rack_input(generator);
    generator->req = NULL;

    if (generator->chunked != NULL)
        h2o_mruby_send_chunked_dispose(generator);
}

static int on_req(h2o_handler_t *_handler, h2o_req_t *req)
{
    auto handler = (h2o_mruby_handler_t *)_handler;
    auto handler_ctx = (h2o_mruby_context_t*)req->conn->ctx->get_handler_context(handler);
    int gc_arena = mrb_gc_arena_save(handler_ctx->mrb);

    auto generator = req->pool.alloc_shared_for<h2o_mruby_generator_t>(1, on_generator_dispose);
    generator->proceed = NULL;
    generator->stop = NULL;
    generator->req = req;
    generator->ctx = (h2o_mruby_context_t*)req->conn->ctx->get_handler_context(handler);
    generator->rack_input = mrb_nil_value();
    generator->chunked = NULL;

    mrb_value env = build_env(generator);

    int is_delegate = 0;
    h2o_mruby_run_fiber(generator, generator->ctx->proc, env, &is_delegate);

    mrb_gc_arena_restore(handler_ctx->mrb, gc_arena);
    if (is_delegate)
        return -1;
    return 0;
}

static void send_response(h2o_mruby_generator_t *generator, mrb_int status, mrb_value resp, int *is_delegate)
{
    mrb_state *mrb = generator->ctx->mrb;
    mrb_value body;
    h2o_iovec_t content = {};

    /* set status */
    generator->req->res.status = (int)status;

    /* set headers */
    if (h2o_mruby_iterate_headers(generator->ctx, mrb_ary_entry(resp, 1), handle_response_header, generator->req) != 0) {
        assert(mrb->exc != NULL);
        goto GotException;
    }

    /* return without processing body, if status is fallthru */
    if (generator->req->res.status == STATUS_FALLTHRU) {
        if (is_delegate != NULL)
            *is_delegate = 1;
        else
            generator->req->delegate_request_deferred(generator->ctx->handler);
        return;
    }

    /* obtain body */
    body = mrb_ary_entry(resp, 2);

    /* flatten body if possible */
    if (mrb_array_p(body)) {
        mrb_int i, len = mrb_ary_len(mrb, body);
        /* calculate the length of the output, while at the same time converting the elements of the output array to string */
        content.len = 0;
        for (i = 0; i != len; ++i) {
            mrb_value e = mrb_ary_entry(body, i);
            if (!mrb_string_p(e)) {
                e = h2o_mruby_to_str(mrb, e);
                if (mrb->exc != NULL)
                    goto GotException;
                mrb_ary_set(mrb, body, i, e);
            }
            content.len += RSTRING_LEN(e);
        }
        /* allocate memory, and copy the response */
        char *dst = content.base = generator->req->pool.alloc_for<char>(content.len);
        for (i = 0; i != len; ++i) {
            mrb_value e = mrb_ary_entry(body, i);
            assert(mrb_string_p(e));
            memcpy(dst, RSTRING_PTR(e), RSTRING_LEN(e));
            dst += RSTRING_LEN(e);
        }
        /* reset body to nil, now that we have read all data */
        body = mrb_nil_value();
    }

    /* use fiber in case we need to call #each */
    if (!mrb_nil_p(body)) {
        generator->req->start_response(generator);
        mrb_value receiver = h2o_mruby_send_chunked_init(generator, body);
        if (!mrb_nil_p(receiver))
            h2o_mruby_run_fiber(generator, receiver, body, 0);
        return;
    }

    /* send the entire response immediately */
    if (generator->req->input.method.isEq("HEAD")) {
        generator->req->start_response(generator);
        generator->req->send(NULL, 0, 1);
    } else {
        if (content.len < generator->req->res.content_length) {
            generator->req->res.content_length = content.len;
        } else {
            content.len = generator->req->res.content_length;
        }
        generator->req->start_response(generator);
        generator->req->send(&content, 1, 1);
    }
    return;

GotException:
    report_exception(generator->req, mrb);
    generator->req->send_error(500, "Internal Server Error", "Internal Server Error", 0);
}

void h2o_mruby_run_fiber(h2o_mruby_generator_t *generator, mrb_value receiver, mrb_value input, int *is_delegate)
{
    mrb_state *mrb = generator->ctx->mrb;
    mrb_value output;
    mrb_int status;

    if (!mrb_obj_eq(mrb, generator->ctx->proc, receiver)) {
        mrb_gc_unregister(mrb, receiver);
        mrb_gc_protect(mrb, receiver);
    }

    h2o_mruby_current_generator = generator;

    while (1) {
        /* send input to fiber */
        output = mrb_funcall_argv(mrb, receiver, generator->ctx->symbols.sym_call, 1, &input);
        if (mrb->exc != NULL)
            goto GotException;
        if (!mrb_array_p(output)) {
            mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "rack app did not return an array"));
            goto GotException;
        }
        /* fetch status */
        mrb_value v = mrb_to_int(mrb, mrb_ary_entry(output, 0));
        if (mrb->exc != NULL)
            goto GotException;
        status = mrb_fixnum(v);
        /* take special action depending on the status code */
        if (status < 0) {
            if (status == H2O_MRUBY_CALLBACK_ID_EXCEPTION_RAISED) {
                mrb->exc = mrb_obj_ptr(mrb_ary_entry(output, 1));
                goto GotException;
            }
            receiver = mrb_ary_entry(output, 1);
            int next_action = H2O_MRUBY_CALLBACK_NEXT_ACTION_IMMEDIATE;
            mrb_value args = mrb_ary_entry(output, 2);
            if (mrb_array_p(args)) {
                switch (status) {
                case H2O_MRUBY_CALLBACK_ID_SEND_CHUNKED_EOS:
                    input = h2o_mruby_send_chunked_eos_callback(generator, receiver, args, &next_action);
                    break;
                case H2O_MRUBY_CALLBACK_ID_HTTP_JOIN_RESPONSE:
                    input = h2o_mruby_http_join_response_callback(generator, receiver, args, &next_action);
                    break;
                case H2O_MRUBY_CALLBACK_ID_HTTP_FETCH_CHUNK:
                    input = h2o_mruby_http_fetch_chunk_callback(generator, receiver, args, &next_action);
                    break;
                default:
                    input = mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "unexpected callback id sent from rack app");
                    break;
                }
            } else {
                input = mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "callback from rack app did not receive an array arg");
            }
            switch (next_action) {
            case H2O_MRUBY_CALLBACK_NEXT_ACTION_STOP:
                return;
            case H2O_MRUBY_CALLBACK_NEXT_ACTION_ASYNC:
                goto Async;
            default:
                assert(next_action == H2O_MRUBY_CALLBACK_NEXT_ACTION_IMMEDIATE);
                break;
            }
            goto Next;
        }
        /* if no special actions were necessary, then the output is a rack response */
        break;
    Next:
        mrb_gc_protect(mrb, receiver);
        mrb_gc_protect(mrb, input);
    }

    h2o_mruby_current_generator = NULL;

    if (!(100 <= status && status <= 999)) {
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "status returned from rack app is out of range"));
        goto GotException;
    }

    /* send the response (unless req is already closed) */
    if (generator->req == NULL)
        return;
    if (generator->req->_generator != NULL) {
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "unexpectedly received a rack response"));
        goto GotException;
    }
    send_response(generator, status, output, is_delegate);
    return;

GotException:
    h2o_mruby_current_generator = NULL;
    if (generator->req != NULL) {
        report_exception(generator->req, mrb);
        if (generator->req->_generator == NULL) {
            generator->req->send_error(500, "Internal Server Error", "Internal Server Error", 0);
        } else {
            h2o_mruby_send_chunked_close(generator);
        }
    }
    return;

Async:
    h2o_mruby_current_generator = NULL;
    if (!mrb_obj_eq(mrb, generator->ctx->proc, receiver))
        mrb_gc_register(mrb, receiver);
    return;
}

h2o_mruby_handler_t *h2o_mruby_register(h2o_pathconf_t *pathconf, h2o_scripting_config_vars_t *vars)
{
    auto handler = pathconf->create_handler<h2o_mruby_handler_t>();

    handler->on_req = on_req;
    handler->config.source.strdup(vars->source);
    if (vars->path != NULL)
        handler->config.path = h2o_strdup(NULL, vars->path, SIZE_MAX).base;

    return handler;
}

mrb_value h2o_mruby_each_to_array(h2o_mruby_context_t *handler_ctx, mrb_value src)
{
    return mrb_funcall_argv(handler_ctx->mrb, mrb_ary_entry(handler_ctx->constants, H2O_MRUBY_PROC_EACH_TO_ARRAY),
                            handler_ctx->symbols.sym_call, 1, &src);
}

static int iterate_headers_handle_pair(h2o_mruby_context_t *handler_ctx, mrb_value name, mrb_value value,
                                       int (*cb)(h2o_mruby_context_t *, h2o_iovec_t, h2o_iovec_t, void *), void *cb_data)
{
    /* convert name and value to string */
    name = h2o_mruby_to_str(handler_ctx->mrb, name);
    if (handler_ctx->mrb->exc != NULL)
        return -1;
    value = h2o_mruby_to_str(handler_ctx->mrb, value);
    if (handler_ctx->mrb->exc != NULL)
        return -1;

    /* call the callback, splitting the values with '\n' */
    const char *vstart = RSTRING_PTR(value), *vend = vstart + RSTRING_LEN(value), *eol;
    while (1) {
        for (eol = vstart; eol != vend; ++eol)
            if (*eol == '\n')
                break;
        if (cb(handler_ctx, h2o_iovec_t::create(RSTRING_PTR(name), RSTRING_LEN(name)), h2o_iovec_t::create(vstart, eol - vstart), cb_data) !=
            0)
            return -1;
        if (eol == vend)
            break;
        vstart = eol + 1;
    }

    return 0;
}

int h2o_mruby_iterate_headers(h2o_mruby_context_t *handler_ctx, mrb_value headers,
                              int (*cb)(h2o_mruby_context_t *, h2o_iovec_t, h2o_iovec_t, void *), void *cb_data)
{
    mrb_state *mrb = handler_ctx->mrb;

    if (!(mrb_hash_p(headers) || mrb_array_p(headers))) {
        headers = h2o_mruby_each_to_array(handler_ctx, headers);
        if (mrb->exc != NULL)
            return -1;
        assert(mrb_array_p(headers));
    }

    if (mrb_hash_p(headers)) {
        mrb_value keys = mrb_hash_keys(mrb, headers);
        mrb_int i, len = mrb_ary_len(mrb, keys);
        for (i = 0; i != len; ++i) {
            mrb_value k = mrb_ary_entry(keys, i);
            mrb_value v = mrb_hash_get(mrb, headers, k);
            if (iterate_headers_handle_pair(handler_ctx, k, v, cb, cb_data) != 0)
                return -1;
        }
    } else {
        assert(mrb_array_p(headers));
        mrb_int i, len = mrb_ary_len(mrb, headers);
        for (i = 0; i != len; ++i) {
            mrb_value pair = mrb_ary_entry(headers, i);
            if (!mrb_array_p(pair)) {
                mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "array element of headers MUST by an array"));
                return -1;
            }
            if (iterate_headers_handle_pair(handler_ctx, mrb_ary_entry(pair, 0), mrb_ary_entry(pair, 1), cb, cb_data) != 0)
                return -1;
        }
    }

    return 0;
}
