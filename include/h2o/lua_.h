/*
 * Copyright (c) 2016 Domingo Alvarez Duarte based on
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Ryosuke Matsumoto
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
#ifndef H20_LUA_H
#define H20_LUA_H

#include "h2o/scripting.h"
#include <lua.hpp>

#define H2O_LUA_MODULE_NAME "h2o_lua"

enum {
    H2O_LUA_LIT_REQUEST_METHOD = H2O_MAX_TOKENS,
    H2O_LUA_LIT_SCRIPT_NAME,
    H2O_LUA_LIT_PATH_INFO,
    H2O_LUA_LIT_QUERY_STRING,
    H2O_LUA_LIT_SERVER_NAME,
    H2O_LUA_LIT_SERVER_ADDR,
    H2O_LUA_LIT_SERVER_PORT,
    H2O_LUA_LIT_CONTENT_LENGTH,
    H2O_LUA_LIT_REMOTE_ADDR,
    H2O_LUA_LIT_REMOTE_PORT,
    H2O_LUA_LIT_REMOTE_USER,
    H2O_LUA_LIT_RACK_URL_SCHEME,
    H2O_LUA_LIT_RACK_MULTITHREAD,
    H2O_LUA_LIT_RACK_MULTIPROCESS,
    H2O_LUA_LIT_RACK_RUN_ONCE,
    H2O_LUA_LIT_RACK_HIJACK_,
    H2O_LUA_LIT_RACK_INPUT,
    H2O_LUA_LIT_RACK_ERRORS,
    H2O_LUA_LIT_SERVER_SOFTWARE,
    H2O_LUA_LIT_SERVER_SOFTWARE_VALUE,
    H2O_LUA_LIT_SEPARATOR_COMMA,
    H2O_LUA_LIT_SEPARATOR_SEMICOLON,
    H2O_LUA_PROC_EACH_TO_ARRAY,
    H2O_LUA_PROC_APP_TO_FIBER,

    /* used by chunked.c */
    H2O_LUA_CHUNKED_PROC_EACH_TO_FIBER,

    /* used by http_request.c */
    H2O_LUA_HTTP_REQUEST_CLASS,
    H2O_LUA_HTTP_INPUT_STREAM_CLASS,

    H2O_LUA_NUM_CONSTANTS
};

struct h2o_lua_handler_t : h2o_scripting_handler_t {

    h2o_lua_handler_t():h2o_scripting_handler_t() {}

    void on_context_init(h2o_context_t *ctx) override;
    void on_context_dispose(h2o_context_t *ctx) override;
};

struct h2o_lua_context_t {
    h2o_lua_handler_t *handler;
    lua_State *L;
};

struct h2o_lua_generator_t : h2o_generator_t {
    h2o_req_t *req; /* becomes NULL once the underlying connection gets terminated */
    lua_State *L;
    int h2o_generator_idx,
        h2o_generator_lua_cb_proceed_idx,
        h2o_generator_lua_cb_data_idx,
        h2o_generator_lua_cb_stop_idx;
};

/* handler/configurator/lua.c */
h2o_lua_handler_t *h2o_lua_register(h2o_pathconf_t *pathconf, h2o_scripting_config_vars_t *vars);
void h2o_lua_register_configurator(h2o_globalconf_t *conf);

#endif

