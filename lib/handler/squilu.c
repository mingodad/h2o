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
#include "h2o/squilu_.h"
#include <sqstdblob.h>
#include <sqstdsystem.h>
#include <sqstdio.h>
#include <sqstdmath.h>
#include <sqstdstring.h>
#include <sqstdaux.h>

#ifdef SQUNICODE
#define scfprintf fwprintf
#define scfopen	_wfopen
#define scvprintf vfwprintf
#else
#define scfprintf fprintf
#define scfopen	fopen
#define scvprintf vfprintf
#endif

//static int show_errors_on_stdout = 1;
//static pthread_mutex_t h2o_squilu_mutex = PTHREAD_MUTEX_INITIALIZER;

static SQRESULT sq_add_reference_to(HSQUIRRELVM v, SQInteger idx, HSQOBJECT &obj)
{
    sq_resetobject(&obj);
    SQRESULT rc = sq_getstackobj(v, idx, &obj);
    if(rc == SQ_OK) sq_addref(v, &obj);
    return rc;
}

static SQRESULT sq_getstr_and_size(HSQUIRRELVM v, SQInteger idx, h2o_iovec_t &dest)
{
    const SQChar *str;
    SQInteger str_len;
    SQInteger rc = sq_getstr_and_size(v, idx, &str, &str_len);
    if(rc == SQ_OK)
    {
        dest.base = (char*)str;
        dest.len = str_len;
    }
    return rc;
}

static void sq_printfunc(HSQUIRRELVM v,const SQChar *s,...)
{
	va_list vl;
	va_start(vl, s);
	scvprintf(stdout, s, vl);
	va_end(vl);
}

static void sq_errorfunc(HSQUIRRELVM v,const SQChar *s,...)
{
	va_list vl;
	va_start(vl, s);
	scvprintf(stderr, s, vl);
	va_end(vl);
}

static void set_h2o_root(HSQUIRRELVM sq)
{
    const char *root_key = "H2O_ROOT";
    const char *root = getenv(root_key);
    if (root == NULL)
        root = root_key;
    sq_pushroottable(sq);
    sq_pushstring(sq, root_key, -1);
    sq_pushstring(sq, root, -1);
    sq_newslot(sq, -3, SQFalse);
    sq_pop(sq, 1);
}

static inline void sq_create_delegate_table(HSQUIRRELVM vm, SQRegFunction *methods, HSQOBJECT *handle)
{
    sq_newtable(vm);
    sq_insert_reg_funcs(vm, methods);
    sq_resetobject(handle);
    sq_getstackobj(vm, -1, handle);
    sq_addref(vm, handle);
}

#define SQ_H2O_PUSH_OBJECT(otype) \
static void sq_push_##otype(HSQUIRRELVM v, otype *obj)\
{\
    SQUserPointer ptr = sq_newuserdata(v, sizeof (otype *));\
    *((otype**)ptr) = obj;\
    sq_settypetag(v, -1, (SQUserPointer)otype##_TAG);\
    sq_pushobject(v, otype##_delegate_table);\
    sq_setdelegate(v, -2);\
}

#define SQ_H2O_GET_OBJECT(otype) \
static otype *sq_get_##otype(HSQUIRRELVM v, SQInteger idx)\
{\
    SQUserPointer obj, utag;\
    SQInteger rc = sq_getuserdata(v, idx, &obj, &utag);\
    if( (rc == SQ_OK) && (utag == otype##_TAG) )\
    {\
        return *((otype**)obj);\
    }\
    return nullptr;\
}

#define SQ_H2O_OBJECT(otype) \
static const char otype##_TAG[] = "__" #otype; \
/*one for each thread*/ \
static __thread HSQOBJECT otype##_delegate_table; \
\
SQ_H2O_PUSH_OBJECT(otype)\
SQ_H2O_GET_OBJECT(otype)

#define SQ_CHECK_H2O_OBJECT(vm, idx, otype, var_name) \
    otype *var_name = sq_get_##otype(v, idx); \
    if(!var_name) return SQ_ERROR;

#define SQ_H2O_OBJECT_GET_STR(otype, var_name, key) \
static SQRESULT sq_##otype##_##key(HSQUIRRELVM v) \
{\
    SQ_CHECK_H2O_OBJECT(v, 1, otype, var_name);\
    sq_pushstring(v, var_name->key, -1);\
    return 1;\
}

#define SQ_H2O_OBJECT_GET_IO_VEC(otype, var_name, key) \
static SQRESULT sq_##otype##_##key(HSQUIRRELVM v) \
{\
    SQ_CHECK_H2O_OBJECT(v, 1, otype, var_name);\
    sq_pushstring(v, var_name->key.base, var_name->key.len);\
    return 1;\
}

#define SQ_H2O_OBJECT_GET_INT(otype, var_name, key) \
static SQRESULT sq_##otype##_##key(HSQUIRRELVM v) \
{\
    SQ_CHECK_H2O_OBJECT(v, 1, otype, var_name);\
    sq_pushinteger(v, var_name->key);\
    return 1;\
}

/*
///Global Config
SQ_H2O_OBJECT(h2o_globalconf_t);
#define GET_h2o_globalconf_AT(v, idx) SQ_CHECK_H2O_OBJECT(v, idx, h2o_globalconf_t, globalconf)
#define CHECK_H2O_GLOBALCONF(v) GET_h2o_globalconf_AT(v, 1)

#define sq_h2o_GLOBALCONF_GET_STR(key) SQ_H2O_OBJECT_GET_STR(h2o_globalconf_t, globalconf, key)
#define sq_h2o_GLOBALCONF_GET_IO_VEC(key) SQ_H2O_OBJECT_GET_IO_VEC(h2o_globalconf_t, globalconf, key)
#define sq_h2o_GLOBALCONF_GET_INT(key) SQ_H2O_OBJECT_GET_INT(h2o_globalconf_t, globalconf, key)

sq_h2o_GLOBALCONF_GET_IO_VEC(server_name);
sq_h2o_GLOBALCONF_GET_INT(max_request_entity_size);
sq_h2o_GLOBALCONF_GET_INT(max_delegations);
sq_h2o_GLOBALCONF_GET_STR(user);
sq_h2o_GLOBALCONF_GET_INT(handshake_timeout);
sq_h2o_GLOBALCONF_GET_INT(_num_config_slots);

#define _DECL_FUNC(name,nparams,tycheck) {_SC(#name),  sq_h2o_globalconf_t_##name,nparams,tycheck}
static SQRegFunction sq_h2o_globalconf_t_methods[] =
{
	_DECL_FUNC(server_name,  1, _SC("u")),
	_DECL_FUNC(max_request_entity_size,  1, _SC("u")),
	_DECL_FUNC(max_delegations,  1, _SC("u")),
	_DECL_FUNC(user,  1, _SC("u")),
	_DECL_FUNC(handshake_timeout,  1, _SC("u")),
	_DECL_FUNC(_num_config_slots,  1, _SC("u")),
	{0,0}
};
#undef _DECL_FUNC

///h2o_hostconf_t
SQ_H2O_OBJECT(h2o_hostconf_t);
#define GET_h2o_hostconf_AT(v, idx) SQ_CHECK_H2O_OBJECT(v, idx, h2o_hostconf_t, hostconf)
#define CHECK_H2O_HOSTCONF(v) GET_h2o_hostconf_AT(v, 1)

#define sq_h2o_HOSTCONF_GET_STR(key) SQ_H2O_OBJECT_GET_STR(h2o_hostconf_t, hostconf, key)
#define sq_h2o_HOSTCONF_GET_IO_VEC(key) SQ_H2O_OBJECT_GET_IO_VEC(h2o_hostconf_t, hostconf, key)
#define sq_h2o_HOSTCONF_GET_INT(key) SQ_H2O_OBJECT_GET_INT(h2o_hostconf_t, hostconf, key)

#define _DECL_FUNC(name,nparams,tycheck) {_SC(#name),  sq_h2o_hostconf_t_##name,nparams,tycheck}
static SQRegFunction sq_h2o_hostconf_t_methods[] =
{
	{0,0}
};
#undef _DECL_FUNC

///h2o_pathconf_t
SQ_H2O_OBJECT(h2o_pathconf_t);
#define GET_h2o_pathconf_AT(v, idx) SQ_CHECK_H2O_OBJECT(v, idx, h2o_pathconf_t, pathconf)
#define CHECK_H2O_HOSTCONF(v) GET_h2o_pathconf_AT(v, 1)

#define sq_h2o_PATHCONF_GET_STR(key) SQ_H2O_OBJECT_GET_STR(h2o_pathconf_t, pathconf, key)
#define sq_h2o_PATHCONF_GET_IO_VEC(key) SQ_H2O_OBJECT_GET_IO_VEC(h2o_pathconf_t, pathconf, key)
#define sq_h2o_PATHCONF_GET_INT(key) SQ_H2O_OBJECT_GET_INT(h2o_pathconf_t, pathconf, key)

#define _DECL_FUNC(name,nparams,tycheck) {_SC(#name),  sq_h2o_pathconf_t_##name,nparams,tycheck}
static SQRegFunction sq_h2o_pathconf_t_methods[] =
{
	{0,0}
};
#undef _DECL_FUNC
*/

///Request
struct sq_h2o_req_t {
    h2o_req_t *req;
    h2o_squilu_handler_t *req_handler;
};

SQ_H2O_OBJECT(h2o_req_t);
#define GET_h2o_request_AT(v, idx) SQ_CHECK_H2O_OBJECT(v, idx, h2o_req_t, req)
#define CHECK_H2O_REQUEST(v) GET_h2o_request_AT(v, 1)

#define sq_h2o_REQ_GET_STR(key) SQ_H2O_OBJECT_GET_STR(h2o_req_t, req, key)
#define sq_h2o_REQ_GET_IO_VEC(key) SQ_H2O_OBJECT_GET_IO_VEC(h2o_req_t, req, key)
#define sq_h2o_REQ_GET_INT(key) SQ_H2O_OBJECT_GET_INT(h2o_req_t, req, key)

sq_h2o_REQ_GET_IO_VEC(authority)
sq_h2o_REQ_GET_IO_VEC(method)
sq_h2o_REQ_GET_IO_VEC(path)
sq_h2o_REQ_GET_IO_VEC(path_normalized)
//sq_h2o_REQ_GET_STR(scheme)
sq_h2o_REQ_GET_IO_VEC(entity)
sq_h2o_REQ_GET_IO_VEC(upgrade)
sq_h2o_REQ_GET_IO_VEC(remote_user)

static SQRESULT sq_h2o_req_t_content_length(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    sq_pushinteger(v, req->entity.len);
    return 1;
}

sq_h2o_REQ_GET_INT(version)
sq_h2o_REQ_GET_INT(bytes_sent)
sq_h2o_REQ_GET_INT(num_reprocessed)
sq_h2o_REQ_GET_INT(num_delegated)
sq_h2o_REQ_GET_INT(http1_is_persistent)
sq_h2o_REQ_GET_INT(res_is_delegated)
sq_h2o_REQ_GET_INT(preferred_chunk_size)

static SQRESULT sq_h2o_req_t_scheme(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    sq_pushstring(v, req->scheme->name.base, req->scheme->name.len);
    return 1;
}

static SQRESULT sq_h2o_req_t_remote_address(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    h2o_socket_address remote_addr = {};
    if(h2o_get_address_info(remote_addr, req->conn, req->conn->callbacks->get_peername))
        return 0;
    sq_pushstring(v, remote_addr.remote_addr, remote_addr.remote_addr_len);
    return 1;
}

static SQRESULT sq_h2o_req_t_remote_port(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    h2o_socket_address remote_addr = {};
    if(h2o_get_address_info(remote_addr, req->conn, req->conn->callbacks->get_peername))
        return 0;
    sq_pushinteger(v, remote_addr.port);
    return 1;
}

static SQRESULT sq_h2o_req_t_server_address(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    h2o_socket_address remote_addr = {};
    if(h2o_get_address_info(remote_addr, req->conn, req->conn->callbacks->get_sockname))
        return 0;
    sq_pushstring(v, remote_addr.remote_addr, remote_addr.remote_addr_len);
    return 1;
}

static SQRESULT sq_h2o_req_t_server_port(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    h2o_socket_address remote_addr = {};
    if(h2o_get_address_info(remote_addr, req->conn, req->conn->callbacks->get_sockname))
        return 0;
    sq_pushinteger(v, remote_addr.port);
    return 1;
}

static SQRESULT sq_h2o_req_t_default_port(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    sq_pushinteger(v, req->scheme->default_port);
    return 1;
}

static SQRESULT sq_h2o_req_t_query_string(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    if(req->query_at != SIZE_MAX)
    {
        sq_pushstring(v, req->path.base + req->query_at + 1, req->path.len - (req->query_at + 1));
    }
    else
    {
        sq_pushstring(v, "", 0);
    }
    return 1;
}

static SQRESULT sq_h2o_req_t_header(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    SQ_FUNC_VARS(v);

    switch(_top_)
    {
    case 2: //get header
        {
            SQ_GET_STRING(v, 2, key);
            size_t header_index = req->headers.find(key, key_size, -1);
            if(header_index != SIZE_MAX)
            {
                h2o_iovec_t *slot = &(req->headers[header_index].value);
                sq_pushstring(v, slot->base, slot->len);
            } else {
                sq_pushnull(v);
            }
            return 1;
        }
        break;
    case 3: //set header
        {
            h2o_iovec_t key;
            sq_getstr_and_size(v, 2, key);
            key.strdup(&req->pool, key);

            h2o_iovec_t value;
            sq_getstr_and_size(v, 2, value);
            value.strdup(&req->pool, value);
            req->addRequestHeader(key, value);
        }
        break;
    }
    return 0;
}

static SQRESULT sq_h2o_req_t_headers_all(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    size_t header_count = req->headers.size;
    sq_newtableex(v, header_count);
    for(size_t i=0; i < header_count; ++i)
    {
        const auto &hdr = req->headers[i];
        sq_pushstring(v, hdr.name->base, hdr.name->len);
        sq_pushstring(v, hdr.value.base, hdr.value.len);
        sq_newslot(v, -3, SQTrue);
    }
    return 1;
}

static SQRESULT sq_h2o_req_t_response_header(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    SQ_FUNC_VARS(v);

    switch(_top_)
    {
    case 2: //get header
        {
            SQ_GET_STRING(v, 2, key);
            size_t header_index = req->res.headers.find(key, key_size, -1);
            if(header_index != SIZE_MAX)
            {
                h2o_iovec_t *slot = &(req->res.headers[header_index].value);
                sq_pushstring(v, slot->base, slot->len);
            } else {
                sq_pushnull(v);
            }
            return 1;
        }
        break;
    case 3: //set header
        {
            h2o_iovec_t key;
            sq_getstr_and_size(v, 2, key);
            key.strdup(&req->pool, key);

            h2o_iovec_t value;
            sq_getstr_and_size(v, 2, value);
            value.strdup(&req->pool, value);
            req->addResponseHeader(key, value);
        }
        break;
    }
    return 0;
}

static SQRESULT sq_h2o_req_t_response_status(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    SQ_FUNC_VARS(v);
    if(_top_ > 1)
    {
        SQ_GET_INTEGER(v, 2, status);
        req->res.status = status;
        return 0;
    }
    sq_pushinteger(v, req->res.status);
    return 1;
}

static SQRESULT sq_h2o_req_t_response_reason(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    h2o_iovec_t reason;
    //reason.base = (char*)luaL_checklstring(v, 2, &reason.len);
    reason.strdup(&req->pool, reason);
    req->res.reason = reason.base;
    return 0;
}

static SQRESULT sq_h2o_req_t_response_content_length(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    SQ_FUNC_VARS(v);
    if(_top_ > 1)
    {
        SQ_GET_INTEGER(v, 2, content_lenght);
        req->res.content_length = content_lenght;
        return 0;
    }
    sq_pushinteger(v, req->res.content_length);
    return 1;
}

static SQRESULT sq_h2o_req_t_send(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    static h2o_generator_t generator = { NULL, NULL };

    h2o_iovec_t body;
    sq_getstr_and_size(v, 2, body);
    body.strdup(&req->pool, body);

    SQInteger is_final = 1;

    if(sq_gettype(v, 3) == OT_STRING)
    {
        h2o_iovec_t content_type;
        sq_getstr_and_size(v, 2, content_type);
        content_type.strdup(&req->pool, content_type);
        req->res.headers.add(&req->pool, H2O_TOKEN_CONTENT_TYPE, content_type.base, content_type.len);
        req->res.content_length = body.len;
        req->res.status = 200;
        req->res.reason = "OK";
    } else {
        if(sq_gettop(v) > 2)
        {
            sq_getinteger(v, 3, &is_final);
        }
    }
    if (!req->_generator) {
        req->start_response(&generator);
    }
    req->send(&body, 1, is_final);
    return 0;
}

static SQRESULT sq_h2o_req_t_send_error0(HSQUIRRELVM v, bool isDeferrered)
{
    CHECK_H2O_REQUEST(v);
    SQ_FUNC_VARS_NO_TOP(v);

    SQ_GET_INTEGER(v, 2, status);
    SQ_GET_STRING(v, 3, reason);
    SQ_GET_STRING(v, 4, body);
    SQ_GET_INTEGER(v, 5, flags);

    h2o_iovec_t iov_reason, iov_body;
    iov_reason.strdup(&req->pool, reason, reason_size);
    iov_body.strdup(&req->pool, body, body_size);

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

static SQRESULT sq_h2o_req_t_send_error(HSQUIRRELVM v)
{
    return sq_h2o_req_t_send_error0(v, false);
}

static SQRESULT sq_h2o_req_t_send_error_deferred(HSQUIRRELVM v)
{
    return sq_h2o_req_t_send_error0(v, true);
}

static SQRESULT sq_h2o_req_t_send_redirect(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    SQ_FUNC_VARS_NO_TOP(v);

    SQ_GET_INTEGER(v, 2, status);
    SQ_GET_STRING(v, 3, reason);
    SQ_GET_STRING(v, 4, url);

    req->send_redirect(status, h2o_strdup(&req->pool, reason, reason_size).base,
                       h2o_strdup(&req->pool, url, url_size));
    return 0;
}

static SQRESULT sq_h2o_req_t_send_redirect_internal(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    SQ_FUNC_VARS_NO_TOP(v);

    SQ_GET_STRING(v, 2, method);
    SQ_GET_STRING(v, 3, url);
    SQ_GET_INTEGER(v, 4, preserve_overrides);

    h2o_iovec_t iov_method, iov_url;
    iov_method.strdup(&req->pool, method, method_size);
    iov_url.strdup(&req->pool, url, url_size);

    req->send_redirect_internal(iov_method, iov_url, preserve_overrides);
    return 0;
}

static SQRESULT sq_h2o_req_t_puth_path_in_link_header(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    SQ_FUNC_VARS_NO_TOP(v);
    SQ_GET_STRING(v, 2, path);

    req->puth_path_in_link_header(path, path_size);
    return 0;
}
/*
static SQRESULT sq_h2o_req_t_delegate_request(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);

    req->delegate_request(req->handler);
    return 0;
}

static SQRESULT sq_h2o_req_t_delegate_request_deferred(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);

    req->delegate_request_deferred(req->handler);
    return 0;
}
*/
static SQRESULT sq_h2o_req_t_reprocess_request(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);

    //req->reprocess_request();
    return 0;
}

static void do_squilu_generator_call(HSQUIRRELVM v, HSQOBJECT &cb, h2o_squilu_generator_t *generator, h2o_req_t *req)
{
    int saved_top = sq_gettop(v);

    sq_pushobject(v, cb);

    if(sq_gettype(v,-1) == OT_CLOSURE) {
        sq_pushroottable(v);
        sq_push_h2o_req_t(v, req);

        bool hasCbData = sq_type(generator->h2o_generator_squilu_cb_data) != OT_NULL;
        if(hasCbData)
        {
            sq_pushobject(v, generator->h2o_generator_squilu_cb_data);
        }

        if (sq_call (v, 2, SQFalse, SQFalse) != SQ_OK) {
            sq_errorfunc(v, "sq_call failed %d\n%s", __LINE__, sq_getlasterror_str(v));
        }
    }
    sq_settop(v, saved_top);
}

static void do_squilu_generator_proceed(h2o_generator_t *_generator, h2o_req_t *req)
{
    auto generator = (h2o_squilu_generator_t *)_generator;
    if(generator->sq)
    {
        do_squilu_generator_call(generator->sq, generator->h2o_generator_squilu_cb_proceed, generator, req);
    }
}

static void do_squilu_generator_stop(h2o_generator_t *_generator, h2o_req_t *req)
{
    auto generator = (h2o_squilu_generator_t *)_generator;
    if(generator->sq)
    {
        do_squilu_generator_call(generator->sq, generator->h2o_generator_squilu_cb_stop, generator, req);
    }
}

static void on_generator_dispose(void *_generator)
{
    auto generator = (h2o_squilu_generator_t *)_generator;

    generator->req = NULL;
    //sq_release(generator->sq, &generator->h2o_generator);
    sq_release(generator->sq, &generator->h2o_generator_squilu_cb_proceed);
    sq_release(generator->sq, &generator->h2o_generator_squilu_cb_stop);
    if(sq_type(generator->h2o_generator_squilu_cb_data) != OT_NULL)
    {
        sq_release(generator->sq, &generator->h2o_generator_squilu_cb_data);
    }
}

static SQRESULT sq_h2o_req_t_start_response(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);

    auto generator = req->pool.alloc_shared_for<h2o_squilu_generator_t>(1, on_generator_dispose);
    h2o_clearmem(generator);
    generator->sq = v;
    generator->proceed = do_squilu_generator_proceed;
    generator->stop = do_squilu_generator_stop;

    sq_add_reference_to(v, 2, generator->h2o_generator_squilu_cb_proceed);
    sq_add_reference_to(v, 3, generator->h2o_generator_squilu_cb_stop);

    if(sq_gettop(v) > 3) {
        sq_add_reference_to(v, 4, generator->h2o_generator_squilu_cb_data);
    } else {
        sq_resetobject(&generator->h2o_generator_squilu_cb_data);
    }
    //sq_add_reference_to(v, generator->h2o_generator);

    req->start_response(generator);
    //trying to call send without seting req->reazon segfaults
    req->send(NULL, 0, 0);
    return 0;
}

static SQRESULT sq_h2o_req_t_console(HSQUIRRELVM v)
{
    CHECK_H2O_REQUEST(v);
    const SQChar *str;
    SQInteger nargs=sq_gettop(v);
    for(int i=2; i<=nargs; ++i){
        if(i>2) scfprintf(stderr,_SC("\t"));
        if(SQ_SUCCEEDED(sq_tostring(v,i))) {
            sq_getstring(v,-1,&str);
            scfprintf(stderr,_SC("%s"),str);
            sq_poptop(v); //remove converted string
        } else {
            return SQ_ERROR;
        }
    }
    scfprintf(stderr,_SC("\n"));
    return 0;
}

#define _DECL_FUNC(name,nparams,tycheck) {_SC(#name),  sq_h2o_req_t_##name,nparams,tycheck}
static SQRegFunction sq_h2o_req_t_methods[] =
{
	_DECL_FUNC(authority,  1, _SC("u")),
	{_SC("host"),  sq_h2o_req_t_authority,  1, _SC("u")},
	_DECL_FUNC(method,  1, _SC("u")),
	_DECL_FUNC(scheme,  1, _SC("u")),
	_DECL_FUNC(path,  1, _SC("u")),
	_DECL_FUNC(path_normalized,  1, _SC("u")),
	_DECL_FUNC(entity,  1, _SC("u")),
	_DECL_FUNC(upgrade,  1, _SC("u")),
	_DECL_FUNC(remote_user,  1, _SC("u")),
	_DECL_FUNC(content_length,  1, _SC("u")),
	_DECL_FUNC(version,  1, _SC("u")),
	_DECL_FUNC(bytes_sent,  1, _SC("u")),
	_DECL_FUNC(num_reprocessed,  1, _SC("u")),
	_DECL_FUNC(num_delegated,  1, _SC("u")),
	_DECL_FUNC(http1_is_persistent,  1, _SC("u")),
	_DECL_FUNC(res_is_delegated,  1, _SC("u")),
	_DECL_FUNC(preferred_chunk_size,  1, _SC("u")),
	_DECL_FUNC(remote_address,  1, _SC("u")),
	_DECL_FUNC(remote_port,  1, _SC("u")),
	_DECL_FUNC(server_address,  1, _SC("u")),
	_DECL_FUNC(server_port,  1, _SC("u")),
	_DECL_FUNC(default_port,  1, _SC("u")),
	_DECL_FUNC(query_string,  1, _SC("u")),
	_DECL_FUNC(console,  -2, _SC("u.")),
	_DECL_FUNC(send,  -2, _SC("u.")),
	_DECL_FUNC(send_redirect,  4, _SC("uiss")),
	_DECL_FUNC(send_redirect_internal,  4, _SC("ussi")),
	_DECL_FUNC(send_error,  5, _SC("uissi")),
	_DECL_FUNC(send_error_deferred,  5, _SC("uissi")),
	_DECL_FUNC(start_response,  -3, _SC("ucc.")),
	_DECL_FUNC(response_content_length,  -1, _SC("ui")),
	_DECL_FUNC(response_status,  -1, _SC("ui")),
	_DECL_FUNC(response_reason,  -1, _SC("us")),
	_DECL_FUNC(header,  -2, _SC("uss")),
	_DECL_FUNC(headers_all,  -2, _SC("u")),
	_DECL_FUNC(response_header,  -2, _SC("uss")),
	_DECL_FUNC(puth_path_in_link_header,  2, _SC("us")),
	{0,0}
};
#undef _DECL_FUNC

SQRESULT sqext_register_H2O(HSQUIRRELVM v)
{
    //sq_create_delegate_table(v, sq_h2o_globalconf_t_methods, &h2o_globalconf_t_delegate_table);
    sq_create_delegate_table(v, sq_h2o_req_t_methods, &h2o_req_t_delegate_table);
    return 0;
}

static HSQUIRRELVM open_squilu()
{
    HSQUIRRELVM sq = sq_open(1024);
    sq_setprintfunc(sq, sq_printfunc, sq_errorfunc);
    sq_pushroottable(sq);
    set_h2o_root(sq);
	sqstd_register_bloblib(sq);
	sqstd_register_iolib(sq);
	sqstd_register_systemlib(sq);
	sqstd_register_mathlib(sq);
	sqstd_register_stringlib(sq);
	sqext_register_H2O(sq);

    return sq;
}

static int h2o_squilu_handle_request(h2o_handler_t *_handler, h2o_req_t *req)
{
    auto handler = (h2o_squilu_handler_t *)_handler;
    auto sq_ctx = (h2o_squilu_context_t*)req->conn->ctx->get_handler_context(handler);
    HSQUIRRELVM v = sq_ctx->sq;
    SQInteger result = 0;
    if(v)
    {
        int saved_top = sq_gettop(v);
        sq_pushstring(v, "h2oHandleRequest", -1);
        if( (sq_getonroottable(v) == SQ_OK) && (sq_gettype(v, -1) == OT_CLOSURE))
        {
            sq_pushroottable(v);
            sq_push_h2o_req_t(v, req);

            if (sq_call (v, 2, SQTrue, SQFalse) == SQ_OK) {
              /* run OK? */
              sq_getinteger(v, -1, &result);
            }
            else
            {
                sq_errorfunc(v, "sq_call failed %d\n%s", __LINE__, sq_getlasterror_str(v));
                result = -1;
            }
        }

        sq_settop(v, saved_top);
    }

    return result;
}

struct squilu_configurator_t : h2o_scripting_configurator_t {

    squilu_configurator_t():h2o_scripting_configurator_t("squilu"){}

    int compile_test(h2o_scripting_config_vars_t *config, char *errbuf) override;

    h2o_scripting_handler_t *pathconf_register(h2o_pathconf_t *pathconf, h2o_scripting_config_vars_t *vars) override
    {
        return (h2o_scripting_handler_t*)h2o_squilu_register(pathconf, vars);
    }
};

int h2o_squilu_compile_code(HSQUIRRELVM sq, h2o_scripting_config_vars_t *config, char *errbuf)
{
    /* parse */
    if(SQ_SUCCEEDED(sq_compilebuffer(sq, config->source.base, config->source.len, config->path, SQTrue, SQTrue))) {
        int callargs = 1;
        sq_pushroottable(sq);
        if(SQ_SUCCEEDED(sq_call(sq, callargs,SQFalse, SQTrue))) {
            return 0;
        }
    }

    return -1;
}

int squilu_configurator_t::compile_test(h2o_scripting_config_vars_t *config, char *errbuf)
{
    HSQUIRRELVM sq = open_squilu();

    if (sq == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_SQUILU_MODULE_NAME);
        abort();
    }
    int ok = h2o_squilu_compile_code(sq, config, errbuf);
    sq_close(sq);

    return ok;
}

h2o_squilu_handler_t *h2o_squilu_register(h2o_pathconf_t *pathconf, h2o_scripting_config_vars_t *vars)
{
    auto handler = pathconf->create_handler<h2o_squilu_handler_t>();

    handler->on_req = h2o_squilu_handle_request;
    handler->config.source.strdup(vars->source);
    if (vars->path != NULL)
        handler->config.path = h2o_strdup(NULL, vars->path, SIZE_MAX).base;

    return handler;
}

void h2o_squilu_register_configurator(h2o_globalconf_t *conf)
{
    auto c = conf->configurator_create<squilu_configurator_t>();
    c->register_configurator(c, conf);
}

void h2o_squilu_handler_t::on_context_init(h2o_context_t *ctx)
{
    auto handler_ctx = h2o_mem_calloc_for<h2o_squilu_context_t>();

    handler_ctx->handler = this;

    /* init squilu in every thread */
    if ((handler_ctx->sq = open_squilu()) == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_SQUILU_MODULE_NAME);
        abort();
    }

    /* compile code (must be done for each thread) */
    int rc = h2o_squilu_compile_code(handler_ctx->sq, &this->config, NULL);

    ctx->set_handler_context(this, handler_ctx);
}

void h2o_squilu_handler_t::on_context_dispose(h2o_context_t *ctx)
{
    auto handler_ctx = (h2o_squilu_context_t*)ctx->get_handler_context(this);

    if (handler_ctx == NULL)
        return;

    sq_close(handler_ctx->sq);
    h2o_mem_free(handler_ctx);
}

