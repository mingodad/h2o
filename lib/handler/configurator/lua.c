/*
 * Copyright (c) 2016 Domingo Alvarez Duarte based on
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku, Ryosuke Matsumoto
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
#include "h2o/lua_.h"

static pthread_mutex_t h2o_lua_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
static void check_h2o_lua_mutex_isLocked(lua_State *L)
{
    if(pthread_mutex_trylock(&h2o_lua_mutex) == 0)
    {
        pthread_mutex_unlock(&h2o_lua_mutex);
        luaL_error(L, "You should aquire h2olib.mutex_[try]lock to use this function !");
    }
}
*/

static int lua_h2o_lua_mutex_trylock(lua_State *L)
{
    lua_pushinteger(L, pthread_mutex_trylock(&h2o_lua_mutex));
    return 1;
}

static int lua_h2o_lua_mutex_lock(lua_State *L)
{
    lua_pushinteger(L, pthread_mutex_lock(&h2o_lua_mutex));
    return 1;
}

static int lua_h2o_lua_mutex_unlock(lua_State *L)
{
    lua_pushinteger(L, pthread_mutex_unlock(&h2o_lua_mutex));
    return 1;
}

static int lua_h2o_usleep(lua_State *L)
{
    unsigned int usec = luaL_checkinteger(L, 1);
    lua_pushinteger(L, usleep(usec));
    return 1;
}

static int lua_mg_url_get_var(lua_State *L)
{
    size_t data_size = 0;
    const char *data = luaL_checklstring(L, 2, &data_size);

    size_t name_size = 0;
    const char *name = luaL_checklstring(L, 3, &name_size);

    const char *start;
    size_t buffer_len;
    int var_len = mg_find_var(data, data_size, name, &start);
    if(var_len > 0){
        buffer_len = var_len+1;
        char *buffer = h2o_mem_alloc_for<char>(buffer_len);
        if(buffer){
            var_len = mg_url_decode(start, var_len, buffer, buffer_len, 1);
            lua_pushlstring(L, buffer, var_len);
            h2o_mem_free(buffer);
            return 1;
        }
    }
    lua_pushnil(L);
    return 1;
}

static int lua_mg_url_decode_base(lua_State *L, int is_form_url_encoded)
{
    size_t src_size = 0;
    const char *src = luaL_checklstring(L, 2, &src_size);

    int dst_len = src_size +1;
    char *dst = h2o_mem_alloc_for<char>(dst_len);
    dst_len = mg_url_decode(src, src_size, dst, dst_len, is_form_url_encoded);
    lua_pushlstring(L, dst, dst_len);
    h2o_mem_free(dst);
    return 1;
}

static int lua_mg_url_decode(lua_State *L)
{
    return lua_mg_url_decode_base(L, 1);
}

static int lua_mg_uri_decode(lua_State *L)
{
    return lua_mg_url_decode_base(L, 0);
}

static int lua_mg_url_encode(lua_State *L)
{
    size_t src_size = 0;
    const char *src = luaL_checklstring(L, 2, &src_size);

    char *dst = mg_url_encode(src);

    lua_pushlstring(L, dst, strlen(dst));
    h2o_mem_free(dst);
    return 1;
}

static const luaL_reg h2o_lib[] =
{
	{"url_get_var",	lua_mg_url_get_var},
	{"url_decode",	lua_mg_url_decode},
	{"url_encode",	lua_mg_url_encode},
	{"uri_decode",	lua_mg_uri_decode},
	{"mutex_trylock",	lua_h2o_lua_mutex_trylock},
	{"mutex_trylock",	lua_h2o_lua_mutex_trylock},
	{"mutex_lock",	    lua_h2o_lua_mutex_lock},
	{"mutex_unlock",	lua_h2o_lua_mutex_unlock},
	{"usleep",      	lua_h2o_usleep},
	{NULL,	NULL}
};

struct lua_h2o_req_t {
    h2o_req_t *req;
    h2o_lua_handler_t *handler;
};

static const char H2O_REQUEST_METATABLE[] = "__h2o_request";
#define CHECK_H2O_REQUEST() \
    lua_h2o_req_t *self = (lua_h2o_req_t *) luaL_checkudata(L, 1, H2O_REQUEST_METATABLE);\
    h2o_req_t *req = self->req

static void lua_push_h2o_req_t(lua_State *L, h2o_lua_handler_t *handler, h2o_req_t *req)
{
    auto ptr = (lua_h2o_req_t*)lua_newuserdata(L, sizeof(lua_h2o_req_t));
    ptr->req = req;
    ptr->handler = handler;

    luaL_getmetatable(L, H2O_REQUEST_METATABLE);
    lua_setmetatable(L, -2);
}

static const char H2O_CONTEXT_METATABLE[] = "__h2o_context";
#define CHECK_H2O_CONTEXT() \
    h2o_context_t *ctx = *(h2o_context_t **) \
    luaL_checkudata(L, 1, H2O_CONTEXT_METATABLE)

static int show_errors_on_stdout = 1;
//printf("%s:%d:%d\n", __FILE__,__LINE__, lua_gettop(L));

static int traceback (lua_State *L) {
  if (!lua_isstring(L, 1))  /* 'message' not a string? */
    return 1;  /* keep it intact */
  lua_getfield(L, LUA_GLOBALSINDEX, "debug");
  if (!lua_istable(L, -1)) {
    lua_pop(L, 1);
    return 1;
  }
  lua_getfield(L, -1, "traceback");
  if (!lua_isfunction(L, -1)) {
    lua_pop(L, 2);
    return 1;
  }
  lua_pushvalue(L, 1);  /* pass error message */
  lua_pushinteger(L, 2);  /* skip this function and traceback */
  lua_call(L, 2, 1);  /* call debug.traceback */
  return 1;
}

#define LUA_H2O_REQ_GET_STR(key) static int lua_h2o_req_get_str_##key(lua_State *L) \
{\
    CHECK_H2O_REQUEST();\
    lua_pushlstring(L, req->key.base, req->key.len);\
    return 1;\
}

LUA_H2O_REQ_GET_STR(authority)
LUA_H2O_REQ_GET_STR(method)
LUA_H2O_REQ_GET_STR(path_normalized)
//LUA_H2O_REQ_GET_STR(scheme)
LUA_H2O_REQ_GET_STR(entity)
LUA_H2O_REQ_GET_STR(upgrade)
LUA_H2O_REQ_GET_STR(remote_user)

#define LUA_H2O_REQ_GET_INT(key) static int lua_h2o_req_get_int_##key(lua_State *L) \
{\
    CHECK_H2O_REQUEST();\
    lua_pushinteger(L, req->key);\
    return 1;\
}

static int lua_h2o_req_get_int_content_length(lua_State *L)
{
    CHECK_H2O_REQUEST();
    lua_pushinteger(L, req->entity.len);
    return 1;
}

LUA_H2O_REQ_GET_INT(version)
LUA_H2O_REQ_GET_INT(bytes_sent)
LUA_H2O_REQ_GET_INT(num_reprocessed)
LUA_H2O_REQ_GET_INT(num_delegated)
LUA_H2O_REQ_GET_INT(http1_is_persistent)
LUA_H2O_REQ_GET_INT(res_is_delegated)
LUA_H2O_REQ_GET_INT(preferred_chunk_size)

static int lua_h2o_req_get_str_scheme(lua_State *L)
{
    CHECK_H2O_REQUEST();
    lua_pushlstring(L, req->scheme->name.base, req->scheme->name.len);
    return 1;
}

static int lua_h2o_req_get_str_remote_address(lua_State *L)
{
    CHECK_H2O_REQUEST();
    h2o_socket_address remote_addr = {};
    if(h2o_get_address_info(remote_addr, req->conn, req->conn->callbacks->get_peername))
        return 0;
    lua_pushlstring(L, remote_addr.remote_addr, remote_addr.remote_addr_len);
    return 1;
}

static int lua_h2o_req_get_int_remote_port(lua_State *L)
{
    CHECK_H2O_REQUEST();
    h2o_socket_address remote_addr = {};
    if(h2o_get_address_info(remote_addr, req->conn, req->conn->callbacks->get_peername))
        return 0;
    lua_pushinteger(L, remote_addr.port);
    return 1;
}

static int lua_h2o_req_get_str_server_address(lua_State *L)
{
    CHECK_H2O_REQUEST();
    h2o_socket_address remote_addr = {};
    if(h2o_get_address_info(remote_addr, req->conn, req->conn->callbacks->get_sockname))
        return 0;
    lua_pushlstring(L, remote_addr.remote_addr, remote_addr.remote_addr_len);
    return 1;
}

static int lua_h2o_req_get_int_server_port(lua_State *L)
{
    CHECK_H2O_REQUEST();
    h2o_socket_address remote_addr = {};
    if(h2o_get_address_info(remote_addr, req->conn, req->conn->callbacks->get_sockname))
        return 0;
    lua_pushinteger(L, remote_addr.port);
    return 1;
}

static int lua_h2o_req_get_int_default_port(lua_State *L)
{
    CHECK_H2O_REQUEST();
    lua_pushinteger(L, req->scheme->default_port);
    return 1;
}

static int lua_h2o_req_get_str_path(lua_State *L)
{
    CHECK_H2O_REQUEST();
    size_t size = req->query_at == SIZE_MAX ? req->path.len : req->query_at;
    lua_pushlstring(L, req->path.base, size);
    return 1;
}

static int lua_h2o_req_get_str_query_string(lua_State *L)
{
    CHECK_H2O_REQUEST();
    if(req->query_at != SIZE_MAX)
    {
        lua_pushlstring(L, req->path.base + req->query_at + 1, req->path.len - (req->query_at + 1));
    }
    else
    {
        lua_pushlstring(L, "", 0);
    }
    return 1;
}

static int lua_h2o_req_get_set_headers0(lua_State *L, h2o_req_t *req, h2o_headers_t &headers)
{
    int argc = lua_gettop(L);
    size_t len;
    const char *key;

    switch(argc)
    {
    case 1: //all headers
        {
            size_t header_count = headers.size;
            lua_createtable (L, 0, header_count);
            for(size_t i=0; i < header_count; ++i)
            {
                const auto &hdr = headers[i];
                lua_pushlstring(L, hdr.name->base, hdr.name->len);
                lua_pushlstring(L, hdr.value.base, hdr.value.len);
                lua_settable (L, -3);
            }
            return 1;
        }
    break;
    case 2: //get header
        {
            key = lua_tolstring(L, 2, &len);
            size_t header_index = headers.find(key, len, SIZE_MAX);
            if(header_index != SIZE_MAX)
            {
                h2o_iovec_t *slot = &(headers[header_index].value);
                lua_pushlstring(L, slot->base, slot->len);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }
        break;
    case 3: //set header
        {
            h2o_iovec_t key;
            key.base = (char*)lua_tolstring(L, 2, &key.len);
            key.strdup(&req->pool, key);

            h2o_iovec_t value;
            value.base = (char*)lua_tolstring(L, 3, &value.len);
            value.strdup(&req->pool, value);
            headers.set(&req->pool, &key, 1, &value, 1);
            return 0;
        }
        break;
    default:
        luaL_error(L, "between 0 and 2 parameters expected for headers function");
    }
    return 0;
}

static int lua_h2o_req_get_set_headers(lua_State *L)
{
    CHECK_H2O_REQUEST();
    return lua_h2o_req_get_set_headers0(L, req, req->headers);
}

static int lua_h2o_req_get_set_response_headers(lua_State *L)
{
    CHECK_H2O_REQUEST();
    return lua_h2o_req_get_set_headers0(L, req, req->res.headers);
}

static int lua_h2o_req_set_int_response_status(lua_State *L)
{
    CHECK_H2O_REQUEST();
    req->res.status = luaL_checkint(L, 2);
    return 0;
}

static int lua_h2o_req_set_str_response_reason(lua_State *L)
{
    CHECK_H2O_REQUEST();
    h2o_iovec_t reason;
    reason.base = (char*)luaL_checklstring(L, 2, &reason.len);
    reason.strdup(&req->pool, reason);
    req->res.reason = reason.base;
    return 0;
}

static int lua_h2o_req_set_int_response_content_length(lua_State *L)
{
    CHECK_H2O_REQUEST();
    req->res.content_length = luaL_checkint(L, 2);
    return 0;
}

static int lua_h2o_req_console(lua_State *L)
{
    //CHECK_H2O_REQUEST();
    int top = lua_gettop(L);
    for(int i=2; i <= top; ++i)
    {
        fprintf(stderr, "%s\t", lua_tostring(L, i));
    }
    fprintf(stderr, "\n");
    return 0;
}

static int lua_h2o_req_send(lua_State *L)
{
    CHECK_H2O_REQUEST();
    static h2o_generator_t generator = { NULL, NULL };

    h2o_iovec_t body;
    body.base = (char*)luaL_checklstring(L, 2, &body.len);
    body.strdup(&req->pool, body);

    int is_final = 1;

    if(lua_isstring(L, 3))
    {
        h2o_iovec_t content_type;
        content_type.base = (char*)lua_tolstring(L, 3, &content_type.len);
        content_type.strdup(&req->pool, content_type);
        req->res.headers.add(&req->pool, H2O_TOKEN_CONTENT_TYPE, content_type.base, content_type.len);
        req->res.content_length = body.len;
        req->res.status = 200;
        req->res.reason = "OK";
    } else {
        is_final = luaL_optint(L, 3, 1);
    }
    if (!req->_generator) {
        req->start_response(&generator);
    }
    req->send(&body, 1, is_final);
    return 0;
}

static int lua_h2o_req_send_redirect(lua_State *L)
{
    CHECK_H2O_REQUEST();

    int status = luaL_checkint(L, 2);
    size_t reason_len = 0;
    const char *reason = luaL_checklstring(L, 3, &reason_len);
    size_t url_len = 0;
    const char *url = luaL_checklstring(L, 4, &url_len);

    req->send_redirect(status, h2o_strdup(&req->pool, reason, reason_len).base, h2o_strdup(&req->pool, url, url_len));
    return 0;
}

static int lua_h2o_req_send_redirect_internal(lua_State *L)
{
    CHECK_H2O_REQUEST();

    size_t method_len = 0;
    const char *method = luaL_checklstring(L, 2, &method_len);
    size_t url_len = 0;
    const char *url = luaL_checklstring(L, 3, &url_len);
    int preserve_overrides = luaL_checkint(L, 4);

    h2o_iovec_t iov_method, iov_url;
    iov_method.strdup(&req->pool, method, method_len);
    iov_url.strdup(&req->pool, url, url_len);

    req->send_redirect_internal(iov_method, iov_url, preserve_overrides);
    return 0;
}
/*
static int lua_h2o_req_reprocess_request(lua_State *L)
{
    CHECK_H2O_REQUEST();

    size_t method_len = 0;
    const char *method = luaL_checklstring(L, 2, &method_len);
    size_t scheme_name_len = 0;
    const char *scheme_name = luaL_checklstring(L, 3, &scheme_name_len);
    int scheme_port = luaL_checkint(L, 4);
    size_t authority_len = 0;
    const char *authority = luaL_checklstring(L, 5, &authority_len);
    size_t path_len = 0;
    const char *path = luaL_checklstring(L, 6, &path_len);
    int is_delegated = luaL_checkint(L, 7);

    h2o_iovec_t iov_method, iov_authority;
    iov_method.strdup(&req->pool, method, method_len);
    iov_authority.strdup(&req->pool, authority, authority_len);


    req->reprocess_request(iov_method, const h2o_url_scheme_t *scheme, iov_authority,
                               h2o_iovec_t path, h2o_req_overrides_t *overrides, is_delegated);
    return 0;
}
*/
static int lua_h2o_req_send_error0(lua_State *L, bool isDeferrered)
{
    CHECK_H2O_REQUEST();

    int status = luaL_checkint(L, 2);
    size_t reason_len = 0;
    const char *reason = luaL_checklstring(L, 3, &reason_len);
    size_t body_len = 0;
    const char *body = luaL_checklstring(L, 4, &body_len);
    int flags = luaL_checkint(L, 5);

    h2o_iovec_t iov_reason, iov_body;
    iov_reason.strdup(&req->pool, reason, reason_len);
    iov_body.strdup(&req->pool, body, body_len);

    if(isDeferrered)
    {
        req->send_error_deferred(status, iov_reason.base, iov_body.base, flags);
    }
    else
    {
        req->send_error(status, iov_reason.base, iov_body.base, flags);
    }

    return 0;
}

static int lua_h2o_req_send_error(lua_State *L)
{
    return lua_h2o_req_send_error0(L, false);
}

static int lua_h2o_req_send_error_deferred(lua_State *L)
{
    return lua_h2o_req_send_error0(L, true);
}

static int lua_h2o_req_send_inline(lua_State *L)
{
    CHECK_H2O_REQUEST();

    size_t body_len = 0;
    const char *body = luaL_checklstring(L, 2, &body_len);

    h2o_iovec_t iov;
    if(body_len)
    {
        iov.strdup(&req->pool, body, body_len);
    }
    else iov = {};

    req->send_inline(iov.base, iov.len);
    return 0;
}

static int lua_h2o_req_puth_path_in_link_header(lua_State *L)
{
    CHECK_H2O_REQUEST();

    size_t path_size = 0;
    const char *path = luaL_checklstring(L, 2, &path_size);

    req->puth_path_in_link_header(path, path_size);
    return 0;
}

static void do_lua_generator_proceed(h2o_generator_t *generator, h2o_req_t *req)
{
    auto self = (h2o_lua_generator_t *)generator;

    lua_State *L = self->L;
    if(L)
    {
        int saved_top = lua_gettop(L);
        lua_pushcfunction(L, traceback);  /* push traceback function */
        int error_func = lua_gettop(L);

        lua_rawgeti(L, LUA_REGISTRYINDEX, self->h2o_generator_lua_cb_proceed_idx);

        if(lua_isfunction(L,-1)) {
            lua_push_h2o_req_t(L, nullptr, req);

            if(self->h2o_generator_lua_cb_data_idx)
            {
                lua_rawgeti(L, LUA_REGISTRYINDEX, self->h2o_generator_lua_cb_data_idx);
            }

            if(lua_pcall(L, self->h2o_generator_lua_cb_data_idx ? 2 : 1, 0, error_func)) {
                size_t error_len;
                const char *error_msg = lua_tolstring(L, -1, &error_len);
                if(show_errors_on_stdout) printf("%s\n", error_msg);
                //write_error_message(conn, error_msg, error_len);
            }
        }
        lua_settop(L, saved_top);
    }
}

static void do_lua_generator_stop(h2o_generator_t *generator, h2o_req_t *req)
{
    auto self = (h2o_lua_generator_t *)generator;

    lua_State *L = self->L;
    if(L)
    {
        int saved_top = lua_gettop(L);
        lua_pushcfunction(L, traceback);  /* push traceback function */
        int error_func = lua_gettop(L);

        lua_rawgeti(L, LUA_REGISTRYINDEX, self->h2o_generator_lua_cb_stop_idx);

        if(lua_isfunction(L,-1)) {
            lua_push_h2o_req_t(L, nullptr, req);

            if(self->h2o_generator_lua_cb_data_idx)
            {
                lua_rawgeti(L, LUA_REGISTRYINDEX, self->h2o_generator_lua_cb_data_idx);
            }

            if(lua_pcall(L, self->h2o_generator_lua_cb_data_idx ? 2 : 1, 0, error_func)) {
                size_t error_len;
                const char *error_msg = lua_tolstring(L, -1, &error_len);
                if(show_errors_on_stdout) printf("%s\n", error_msg);
                //write_error_message(conn, error_msg, error_len);
            }
        }
///fixme generator on_dispose do this ?
        luaL_unref(L, LUA_REGISTRYINDEX, self->h2o_generator_lua_cb_proceed_idx);
        luaL_unref(L, LUA_REGISTRYINDEX, self->h2o_generator_lua_cb_stop_idx);
        if(self->h2o_generator_lua_cb_data_idx)
        {
            luaL_unref(L, LUA_REGISTRYINDEX, self->h2o_generator_lua_cb_data_idx);
        }
        luaL_unref(L, LUA_REGISTRYINDEX, self->h2o_generator_idx);

        lua_settop(L, saved_top);
    }
}

static void on_generator_dispose(void *_generator)
{
    auto lg = (h2o_lua_generator_t *)_generator;

    lg->req = NULL;
    luaL_unref(lg->L, LUA_REGISTRYINDEX, lg->h2o_generator_lua_cb_proceed_idx);
    luaL_unref(lg->L, LUA_REGISTRYINDEX, lg->h2o_generator_lua_cb_stop_idx);
    luaL_unref(lg->L, LUA_REGISTRYINDEX, lg->h2o_generator_idx);
    if(lg->h2o_generator_lua_cb_data_idx) luaL_unref(lg->L, LUA_REGISTRYINDEX, lg->h2o_generator_lua_cb_data_idx);
}

static int lua_h2o_req_start_response(lua_State *L)
{
    CHECK_H2O_REQUEST();

    if (lua_type(L, 2) != LUA_TFUNCTION) luaL_error(L, "function to proceed expected");
    if (lua_type(L, 3) != LUA_TFUNCTION) luaL_error(L, "function to stop expected");

    auto lg = req->pool.alloc_shared_for<h2o_lua_generator_t>(1, on_generator_dispose);
    h2o_clearmem(lg);
    lg->L = L;
    lg->proceed = do_lua_generator_proceed;
    lg->stop = do_lua_generator_stop;

    lua_pushvalue(L, 2);
    lg->h2o_generator_lua_cb_proceed_idx = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_pushvalue(L, 3);
    lg->h2o_generator_lua_cb_stop_idx = luaL_ref(L, LUA_REGISTRYINDEX);

    if(lua_gettop(L) > 3) {
        lua_pushvalue(L, 4);
        lg->h2o_generator_lua_cb_data_idx = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        lg->h2o_generator_lua_cb_data_idx = 0;
    }
    lg->h2o_generator_idx = luaL_ref(L, LUA_REGISTRYINDEX);

    req->start_response(lg);
    //trying to call send without seting req->reazon segfaults
    req->send(NULL, 0, 0);
    return 0;
}

#define LUA_REG_REQ_GET_STR_FUNC(name) { #name, lua_h2o_req_get_str_##name }
#define LUA_REG_REQ_GET_INT_FUNC(name) { #name, lua_h2o_req_get_int_##name }
#define LUA_REG_REQ_SET_STR_FUNC(name) { #name, lua_h2o_req_set_str_##name }
#define LUA_REG_REQ_SET_INT_FUNC(name) { #name, lua_h2o_req_set_int_##name }

static const luaL_reg reqFunctions[] = {
    LUA_REG_REQ_GET_STR_FUNC(authority),
    LUA_REG_REQ_GET_INT_FUNC(bytes_sent),
    {"console", lua_h2o_req_console},
    LUA_REG_REQ_GET_INT_FUNC(content_length),
    LUA_REG_REQ_GET_INT_FUNC(default_port),
    LUA_REG_REQ_GET_STR_FUNC(entity),
    {"headers", lua_h2o_req_get_set_headers},
    {"host", lua_h2o_req_get_str_authority},
    LUA_REG_REQ_GET_INT_FUNC(http1_is_persistent),
    LUA_REG_REQ_GET_STR_FUNC(method),
    LUA_REG_REQ_GET_INT_FUNC(num_delegated),
    LUA_REG_REQ_GET_INT_FUNC(num_reprocessed),
    LUA_REG_REQ_GET_STR_FUNC(path),
    LUA_REG_REQ_GET_STR_FUNC(path_normalized),
    LUA_REG_REQ_GET_INT_FUNC(preferred_chunk_size),
    {"puth_path_in_link_header", lua_h2o_req_puth_path_in_link_header},
    LUA_REG_REQ_GET_STR_FUNC(query_string),
    LUA_REG_REQ_GET_STR_FUNC(remote_address),
    LUA_REG_REQ_GET_INT_FUNC(remote_port),
    LUA_REG_REQ_GET_STR_FUNC(remote_user),
    LUA_REG_REQ_GET_INT_FUNC(res_is_delegated),
    LUA_REG_REQ_SET_INT_FUNC(response_content_length),
    {"response_headers", lua_h2o_req_get_set_response_headers},
    LUA_REG_REQ_SET_STR_FUNC(response_reason),
    LUA_REG_REQ_SET_INT_FUNC(response_status),
    LUA_REG_REQ_GET_STR_FUNC(scheme),
    {"send", lua_h2o_req_send},
    {"send_error", lua_h2o_req_send_error},
    {"send_error_deferred", lua_h2o_req_send_error_deferred},
    {"send_inline", lua_h2o_req_send_inline},
    {"send_redirect", lua_h2o_req_send_redirect},
    {"send_redirect_internal", lua_h2o_req_send_redirect_internal},
    //{"reprocess_request", lua_h2o_req_reprocess_request},
    LUA_REG_REQ_GET_STR_FUNC(server_address),
    LUA_REG_REQ_GET_INT_FUNC(server_port),
    {"start_response", lua_h2o_req_start_response},
    LUA_REG_REQ_GET_STR_FUNC(upgrade),
    LUA_REG_REQ_GET_INT_FUNC(version),
    { NULL, NULL }
};

#if 0
static int h2o_lua_call_with_context(h2o_context_t *_ctx, const char *func_name)
{
    auto lua_ctx = (h2o_lua_context_t*)_ctx;
    lua_State *L = lua_ctx->L;
    int result = 0;
    if(L)
    {
        int saved_top = lua_gettop(L);
        lua_pushcfunction(L, traceback);  /* push traceback function */
        int error_func = lua_gettop(L);

        lua_getglobal(L, func_name);
        if(lua_isfunction(L,-1)) {
            *(h2o_lua_context_t **)lua_newuserdata(L, sizeof (h2o_lua_context_t *)) = lua_ctx;
            luaL_getmetatable(L, H2O_CONTEXT_METATABLE);
            lua_setmetatable(L, -2);

            if(lua_pcall(L, 1, 1, error_func)) {
                size_t error_len;
                const char *error_msg = lua_tolstring(L, -1, &error_len);
                if(show_errors_on_stdout) printf("%s\n", error_msg);
                //write_error_message(conn, error_msg, error_len);
                result = 0;
            } else {
                result = lua_tointeger(L, -1);
            }
        }
        lua_settop(L, saved_top);
    }

    return result;
}

static int my_h2o_lua_handler(h2o_handler_t *self, h2o_req_t *req);

static int register_handler_on_host_by_host(h2o_globalconf_t *cfg, const char *host,
                                            const char *path, on_req_handler_ptr cb)
{
    return 0;
}

static int lua_h2o_context_register_handler_on_host(lua_State *L)
{
    CHECK_H2O_CONTEXT();
    check_h2o_lua_mutex_isLocked(L);
    const char *path = luaL_checkstring(L, 2);
    const char *host = luaL_checkstring(L, 3);
    h2o_globalconf_t *globalconf = ctx->globalconf;
    int result = register_handler_on_host_by_host(globalconf, host, path, my_h2o_lua_handler);
    lua_pushboolean(L, result);
    return 1;
}

static int lua_h2o_context_register_handler_global(lua_State *L)
{
    CHECK_H2O_CONTEXT();
    //exclusive access to prevent multiple threads changing at the same time
    check_h2o_lua_mutex_isLocked(L);
    const char *path = luaL_checkstring(L, 2);
    int result = register_handler_global(ctx->globalconf, path, my_h2o_lua_handler);
    lua_pushboolean(L, result);
    return 1;
}

static h2o_hostconf_t *h2o_config_register_host(h2o_globalconf_t *cfg, const char *host)
{
    return nullptr;
}

static int lua_h2o_context_register_host(lua_State *L)
{
    CHECK_H2O_CONTEXT();
    //exclusive access to prevent multiple threads changing at the same time
    check_h2o_lua_mutex_isLocked(L);
    const char *host = luaL_checkstring(L, 2);
    h2o_hostconf_t *result = h2o_config_register_host(ctx->globalconf, host);
    lua_pushboolean(L, result != NULL);
    return 1;
}

static void sort_handler_global(h2o_globalconf_t *cfg)
{

}

static int lua_h2o_context_sort_handler_global(lua_State *L)
{
    CHECK_H2O_CONTEXT();
    //exclusive access to prevent multiple threads changing at the same time
    check_h2o_lua_mutex_isLocked(L);
    sort_handler_global(ctx->globalconf);
    return 0;
}

static const luaL_reg contextFunctions[] = {
    {"register_handler_on_host", lua_h2o_context_register_handler_on_host},
    {"register_handler_global", lua_h2o_context_register_handler_global},
    {"register_host", lua_h2o_context_register_host},
    {"sort_handler_global", lua_h2o_context_sort_handler_global},
    { NULL, NULL }
};
#endif

int
#if defined(_WIN32)
__declspec(dllexport)
#endif /* _WIN32 */
luaopen_h2o(lua_State *L)
{
    //old_clib_getsym_func_ptr = set_lj_clib_get_sym(my_clib_getsym_func);
    int i;
    /* Create the metatable and put it on the stack. */
    luaL_newmetatable(L, H2O_REQUEST_METATABLE);
    lua_newtable(L);
	for (i=0; reqFunctions[i].name; i++)
	{
		lua_pushcfunction(L, reqFunctions[i].func);
		lua_setfield(L, -2, reqFunctions[i].name);
	}
	lua_setfield(L, -2, "__index");
    lua_pop(L, 1);

/*
    luaL_newmetatable(L, H2O_CONTEXT_METATABLE);
    lua_newtable(L);
	for (i=0; contextFunctions[i].name; i++)
	{
		lua_pushcfunction(L, contextFunctions[i].func);
		lua_setfield(L, -2, contextFunctions[i].name);
	}
	lua_setfield(L, -2, "__index");
    lua_pop(L, 1);
*/
    luaL_openlib(L, "h2olib", h2o_lib, 0);

    return 1;
}

LUALIB_API int luaopen_lsqlite3(lua_State *L);
LUALIB_API int luaopen_base64(lua_State *L);
LUALIB_API int luaopen_mixlua(lua_State *L);
LUALIB_API int luaopen_memoryfile(lua_State *L);
LUALIB_API int luaopen_lfs(lua_State *L);
LUALIB_API int luaopen_mime_core(lua_State *L);
LUALIB_API int luaopen_socket_core(lua_State *L);
LUALIB_API int luaopen_json(lua_State* L);
//LUALIB_API int luaopen_random(lua_State *L);

/*
static lua_modules_preload_st my_extra_modules[] = {
  {"base64", luaopen_base64},
  {"lfs", luaopen_lfs},
  {"memoryfile", luaopen_memoryfile},
  {"mixlua", luaopen_mixlua},
  {"lsqlite3", luaopen_lsqlite3},
  {"mime.core", luaopen_mime_core},
  {"socket.core", luaopen_socket_core},
  {"json", luaopen_json},
  {NULL, NULL}
};
*/

static void h2o_lua_open_libs(lua_State *L) {
    if(L)
    {
        luaL_openlibs(L);
        luaopen_h2o(L);
        /*
        lua_preload_modules(L, my_extra_modules);
        lua_pushcfunction(L, lua_mg_uri_decode);
        lua_setglobal(L, "uri_decode");
        lua_pushcfunction(L, lua_mg_url_decode);
        lua_setglobal(L, "url_decode");
        lua_pushcfunction(L, lua_mg_url_encode);
        lua_setglobal(L, "url_encode");
        lua_pushcfunction(L, lua_mg_md5);
        lua_setglobal(L, "mg_md5");
        lua_pushstring(L, mg_get_option(ctx, "document_root"));
        lua_setglobal(L, "APP_ROOT_FOLDER");
        lua_pushcfunction(L, lua_debug_print);
        lua_setglobal(L, "debug_print");
        */

        //int saved_top = lua_gettop(L);
        //(void) luaL_dofile(L, "h2o-on-thread-start.lua");
        //h2o_lua_call_with_context(_ctx, "h2oOnThreadStart");
        //lua_settop(L, saved_top);
    }
}

/*
static void h2o_lua_close_libs(h2o_context_t *_ctx) {
    auto lua_ctx = (h2o_lua_context_t*)_ctx;
    lua_State *L = lua_ctx->L;
    if(L)
    {
        //h2o_lua_call_with_context(_ctx, "h2oOnThreadEnd");
        lua_close(L);
    }
}
*/

static int h2o_lua_handle_request(h2o_handler_t *_handler, h2o_req_t *req)
{
    auto handler = (h2o_lua_handler_t *)_handler;
    auto lua_ctx = (h2o_lua_context_t*)req->conn->ctx->get_handler_context(handler);
    lua_State *L = lua_ctx->L;
    int result = 0;
    if(L)
    {
        if(handler->config.debug)
        {
            /*
            !!! attention if debug is enabled use only one thread !!!
            */
            if(handler->reload_scripting_file(lua_ctx, nullptr))
            {
                return -1;
            }
        }

        int saved_top = lua_gettop(L);
        lua_pushcfunction(L, traceback);  /* push traceback function */
        int error_func = lua_gettop(L);

        lua_getglobal(L, H2O_SCRIPTING_ENTRY_POINT);
        if(lua_isfunction(L,-1)) {
            lua_push_h2o_req_t(L, handler, req);

            if(lua_pcall(L, 1, 1, error_func)) {
                size_t error_len;
                const char *error_msg = lua_tolstring(L, -1, &error_len);
                if(show_errors_on_stdout) printf("%s\n", error_msg);
                //write_error_message(conn, error_msg, error_len);
                result = 0;
            } else {
                result = lua_tointeger(L, -1);
            }
        };
        lua_settop(L, saved_top);
    }

    return result;
}

struct lua_configurator_t : h2o_scripting_configurator_t {

    lua_configurator_t():h2o_scripting_configurator_t("lua"){}

    int compile_test(h2o_scripting_config_vars_t *config, char *errbuf, size_t errbuf_size) override;

    h2o_scripting_handler_t *pathconf_register(h2o_pathconf_t *pathconf, h2o_scripting_config_vars_t *vars) override
    {
        return (h2o_scripting_handler_t*)h2o_lua_register(pathconf, vars);
    }
};

static void set_h2o_root(lua_State *L)
{
    const char *root = getenv("H2O_ROOT");
    if (root == NULL)
        root = H2O_TO_STR(H2O_ROOT);
    lua_pushstring(L, root);
    lua_setglobal(L, "H2O_ROOT");
}

int h2o_lua_handler_t::reload_scripting_file(void *ctx, h2o_scripting_config_vars_t *config_var)
{
    auto lua_ctx = (h2o_lua_context_t*)ctx;

	lua_settop(lua_ctx->L, 0);

	//make a prvate copy to allow work with multi threads
    h2o_scripting_config_vars_t config_debug = {};
    //we only care for debug and path
    config_debug.debug = 1;
    config_debug.path = this->config.path;

    return super::reload_scripting_file(ctx, &config_debug);
}

int h2o_lua_compile_code(lua_State *L, h2o_scripting_config_vars_t *config, char *errbuf, size_t errbuf_size)
{
    set_h2o_root(L);

    /* parse */
    int result = luaL_loadbuffer(L, config->source.base, config->source.len, config->path)
        || lua_pcall(L, 0, 0, 0);
    if (result && !lua_isnil(L, -1)) {
        const char *msg = lua_tostring(L, -1);
        if (msg == NULL) msg = "(error object is not a string)";
        fprintf(stderr, "%s: %s\n", H2O_LUA_MODULE_NAME, msg);
        lua_pop(L, 1);
    }

    return result;
}

int lua_configurator_t::compile_test(h2o_scripting_config_vars_t *config, char *errbuf, size_t errbuf_size)
{
    lua_State *L = lua_open();

    if (L == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_LUA_MODULE_NAME);
        abort();
    }
    h2o_lua_open_libs(L);
    int ok = h2o_lua_compile_code(L, config, errbuf, errbuf_size);
    lua_close(L);

    return ok;
}

h2o_lua_handler_t *h2o_lua_register(h2o_pathconf_t *pathconf, h2o_scripting_config_vars_t *vars)
{
    auto handler = pathconf->create_handler<h2o_lua_handler_t>();

    handler->on_req = h2o_lua_handle_request;
    handler->config.source.strdup(vars->source);
    if (vars->path != NULL)
        handler->config.path = h2o_strdup(NULL, vars->path, SIZE_MAX).base;

    return handler;
}

void h2o_lua_register_configurator(h2o_globalconf_t *conf)
{
    auto c = conf->configurator_create<lua_configurator_t>();
    c->register_configurator(c, conf);
}

void h2o_lua_handler_t::on_context_init(h2o_context_t *ctx)
{
    auto handler_ctx = h2o_mem_calloc_for<h2o_lua_context_t>();
    char errbuf[1024];

    handler_ctx->handler = this;

    /* init lua in every thread */
    if ((handler_ctx->L = lua_open()) == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_LUA_MODULE_NAME);
        abort();
    }

    h2o_lua_open_libs(handler_ctx->L);

    /* compile code (must be done for each thread) */
    /*int rc =*/ h2o_lua_compile_code(handler_ctx->L, &this->config, errbuf, sizeof(errbuf));

    ctx->set_handler_context(this, handler_ctx);
}

void h2o_lua_handler_t::on_context_dispose(h2o_context_t *ctx)
{
    auto handler_ctx = (h2o_lua_context_t*)ctx->get_handler_context(this);

    if (handler_ctx == NULL)
        return;

    lua_close(handler_ctx->L);
    h2o_mem_free(handler_ctx);
}

int h2o_lua_handler_t::compile_code(void *ctx, h2o_scripting_config_vars_t *config_var)
{
    char errbuf[1024];
    auto handler_ctx = (h2o_lua_context_t*)ctx;
    return h2o_lua_compile_code(handler_ctx->L, config_var, errbuf, sizeof(errbuf));
}
