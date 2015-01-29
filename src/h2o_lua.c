typedef void *(*clib_getsym_func_ptr)(void *cl, const char *name);
extern clib_getsym_func_ptr set_lj_clib_get_sym(clib_getsym_func_ptr funcPtr);

static clib_getsym_func_ptr old_clib_getsym_func_ptr;

void *my_clib_getsym_func(void *cl, const char *name)
{
    void *funcPtr= NULL ;
    //printf("my_clib_getsym_func => %s\n", name);
    if(strcmp(name, "myprintf") == 0)
    {
        funcPtr = printf;
    }
    else
    {
        funcPtr = (*old_clib_getsym_func_ptr)(cl, name);
    }
    return funcPtr;
}

static pthread_mutex_t h2o_lua_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char H2O_REQUEST_METATABLE[] = "_h2o_request";
#define CHECK_H2O_REQUEST() \
    h2o_req_t *req = *(h2o_req_t **) \
    luaL_checkudata(L, 1, H2O_REQUEST_METATABLE)

static const char H2O_CONTEXT_METATABLE[] = "_h2o_context";
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
LUA_H2O_REQ_GET_STR(path)
LUA_H2O_REQ_GET_STR(path_normalized)
LUA_H2O_REQ_GET_STR(scheme)
LUA_H2O_REQ_GET_STR(entity)
LUA_H2O_REQ_GET_STR(upgrade)

#define LUA_H2O_REQ_GET_INT(key) static int lua_h2o_req_get_int_##key(lua_State *L) \
{\
    CHECK_H2O_REQUEST();\
    lua_pushinteger(L, req->key);\
    return 1;\
}

LUA_H2O_REQ_GET_INT(version)
LUA_H2O_REQ_GET_INT(bytes_sent)
LUA_H2O_REQ_GET_INT(http1_is_persistent)

static int lua_h2o_req_get_set_header(lua_State *L)
{
    CHECK_H2O_REQUEST();
    int argc = lua_gettop(L);
    size_t len;
    const char *key;

    switch(argc)
    {
    case 2: //get header
        {
            key = lua_tolstring(L, 2, &len);
            size_t header_index = h2o_find_header_by_str(&req->headers, key, len, -1);
            if(header_index != -1)
            {
                h2o_iovec_t *slot = &(req->headers.entries[header_index].value);
                lua_pushlstring(L, slot->base, slot->len);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }
        break;
    case 3: //set header
        {
            size_t value_len;
            key = lua_tolstring(L, 2, &len);
            const char *value = lua_tolstring(L, 3, &value_len);
            h2o_add_header_by_str(&req->pool, &req->res.headers, key, len, 0, value, value_len);
            return 0;
        }
        break;
    default:
        luaL_error(L, "at least one parameter is required for req:header function");
    }
    return 0;
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
    reason.base = luaL_checklstring(L, 2, &reason.len);
    reason = h2o_strdup(&req->pool, reason.base, reason.len);
    req->res.reason = reason.base;
    return 0;
}

static int lua_h2o_req_set_int_response_content_length(lua_State *L)
{
    CHECK_H2O_REQUEST();
    req->res.content_length = luaL_checkint(L, 2);
    return 0;
}

static int lua_h2o_req_send(lua_State *L)
{
    CHECK_H2O_REQUEST();
    static h2o_generator_t generator = { NULL, NULL };

    h2o_iovec_t body;
    body.base = luaL_checklstring(L, 2, &body.len);
    int is_final = 1;

    if(lua_isstring(L, 3))
    {
        h2o_iovec_t content_type;
        content_type.base = lua_tolstring(L, 3, &content_type.len);
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, content_type.base, content_type.len);
        req->res.content_length = body.len;
        req->res.status = 200;
        req->res.reason = "OK";
    } else {
        is_final = luaL_optint(L, 3, 1);
    }
    if (!req->_generator) {
        h2o_start_response(req, &generator);
    }
    h2o_send(req, &body, 1, is_final);
    return 0;
}

#define LUA_REG_REQ_GET_STR_FUNC(name) { #name, lua_h2o_req_get_str_##name }
#define LUA_REG_REQ_GET_INT_FUNC(name) { #name, lua_h2o_req_get_int_##name }

static const luaL_reg reqFunctions[] = {
    LUA_REG_REQ_GET_STR_FUNC(authority),
    {"host", lua_h2o_req_get_str_authority},
    LUA_REG_REQ_GET_STR_FUNC(method),
    LUA_REG_REQ_GET_STR_FUNC(path),
    LUA_REG_REQ_GET_STR_FUNC(path_normalized),
    LUA_REG_REQ_GET_STR_FUNC(scheme),
    LUA_REG_REQ_GET_STR_FUNC(entity),
    LUA_REG_REQ_GET_STR_FUNC(upgrade),
    LUA_REG_REQ_GET_INT_FUNC(version),
    LUA_REG_REQ_GET_INT_FUNC(bytes_sent),
    LUA_REG_REQ_GET_INT_FUNC(http1_is_persistent),
    {"header", lua_h2o_req_get_set_header},
    {"send", lua_h2o_req_send},
    {"response_status", lua_h2o_req_set_int_response_status},
    {"response_reason", lua_h2o_req_set_str_response_reason},
    {"response_content_length", lua_h2o_req_set_int_response_content_length},
    { NULL, NULL }
};

static int h2o_lua_call_with_context(h2o_context_t *ctx, const char *func_name)
{
    lua_State *L = ctx->L;
    int result = 0;
    if(L)
    {
        int saved_top = lua_gettop(L);
        lua_pushcfunction(L, traceback);  /* push traceback function */
        int error_func = lua_gettop(L);

        lua_getglobal(L, func_name);
        if(lua_isfunction(L,-1)) {
            *(h2o_context_t **)lua_newuserdata(L, sizeof (h2o_context_t *)) = ctx;
            luaL_getmetatable(L, H2O_CONTEXT_METATABLE);
            lua_setmetatable(L, -2);

            if(lua_pcall(L, 1, 1, error_func)) {
                size_t error_len;
                const char *error_msg = lua_tolstring(L, -1, &error_len);
                if(show_errors_on_stdout) printf("%s\n", error_msg);
                //write_error_message(conn, error_msg, error_len);
                result = 0;
            } else {
                result = lua_toboolean(L, -1) ? 1 : 0;
            }
        };
        lua_settop(L, saved_top);
    }

    return result;
}

static int my_h2o_lua_handler(h2o_handler_t *self, h2o_req_t *req);

static int lua_h2o_context_register_handler_on_host(lua_State *L)
{
    CHECK_H2O_CONTEXT();
    h2o_iovec_t host;
    const char *path = luaL_checkstring(L, 2);
    host.base = luaL_checklstring(L, 3, &host.len);
    int result = 0;

    size_t i;
    h2o_globalconf_t *globalconf = ctx->globalconf;
    //exclusive access to prevent multiple threads changing at the same time
    pthread_mutex_lock(&h2o_lua_mutex);
    for (i = 0; i != globalconf->hosts.size; ++i) {
        h2o_hostconf_t *hostconf = globalconf->hosts.entries + i;
        if(h2o_lcstris(hostconf->hostname.base, hostconf->hostname.len, host.base, host.len))
        {
            register_handler_on_host(hostconf, path, my_h2o_lua_handler);
            result = 1;
            break;
        }
    }
    pthread_mutex_unlock(&h2o_lua_mutex);
    lua_pushboolean(L, result);
    return 1;
}

static int lua_h2o_context_register_handler_global(lua_State *L)
{
    CHECK_H2O_CONTEXT();
    const char *path = luaL_checkstring(L, 2);
    int result = 0;
    //exclusive access to prevent multiple threads changing at the same time
    pthread_mutex_lock(&h2o_lua_mutex);
    result = register_handler_global(ctx->globalconf, path, my_h2o_lua_handler);
    pthread_mutex_unlock(&h2o_lua_mutex);
    lua_pushboolean(L, result);
    return 1;
}

static int lua_h2o_context_sort_handler_global(lua_State *L)
{
    CHECK_H2O_CONTEXT();
    //exclusive access to prevent multiple threads changing at the same time
    pthread_mutex_lock(&h2o_lua_mutex);
    sort_handler_global(ctx->globalconf);
    pthread_mutex_unlock(&h2o_lua_mutex);
    return 0;
}

static const luaL_reg contextFunctions[] = {
    {"register_handler_on_host", lua_h2o_context_register_handler_on_host},
    {"register_handler_global", lua_h2o_context_register_handler_global},
    {"sort_handler_global", lua_h2o_context_sort_handler_global},
    { NULL, NULL }
};

int
#if defined(_WIN32)
__declspec(dllexport)
#endif /* _WIN32 */
luaopen_h2o(lua_State *L)
{
    old_clib_getsym_func_ptr = set_lj_clib_get_sym(my_clib_getsym_func);
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

    luaL_newmetatable(L, H2O_CONTEXT_METATABLE);
    lua_newtable(L);
	for (i=0; contextFunctions[i].name; i++)
	{
		lua_pushcfunction(L, contextFunctions[i].func);
		lua_setfield(L, -2, contextFunctions[i].name);
	}
	lua_setfield(L, -2, "__index");
    lua_pop(L, 1);

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

static void h2o_lua_open_libs(h2o_context_t *ctx) {
    lua_State *L = ctx->L = luaL_newstate();
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
        (void) luaL_dofile(L, "h2o-on-thread-start.lua");
        h2o_lua_call_with_context(ctx, "h2oOnThreadStart");
        //lua_settop(L, saved_top);
    }
}

static void h2o_lua_close_libs(h2o_context_t *ctx) {
    lua_State *L = ctx->L;
    if(L)
    {
        h2o_lua_call_with_context(ctx, "h2oOnThreadEnd");
        lua_close(L);
    }
}


static int h2o_lua_handle_request(h2o_req_t *req)
{
    lua_State *L = req->conn->ctx->L;
    int result = 0;
    if(L)
    {
        int saved_top = lua_gettop(L);
        lua_pushcfunction(L, traceback);  /* push traceback function */
        int error_func = lua_gettop(L);

        lua_getglobal(L, "h2oManageRequest");
        if(lua_isfunction(L,-1)) {
            *(h2o_req_t **)lua_newuserdata(L, sizeof (h2o_req_t *)) = req;
            luaL_getmetatable(L, H2O_REQUEST_METATABLE);
            lua_setmetatable(L, -2);

            if(lua_pcall(L, 1, 1, error_func)) {
                size_t error_len;
                const char *error_msg = lua_tolstring(L, -1, &error_len);
                if(show_errors_on_stdout) printf("%s\n", error_msg);
                //write_error_message(conn, error_msg, error_len);
                result = 0;
            } else {
                result = lua_toboolean(L, -1) ? 1 : 0;
            }
        };
        lua_settop(L, saved_top);
    }

    return result;
}

static int my_h2o_lua_handler(h2o_handler_t *self, h2o_req_t *req)
{
    //printf("===Request path = %s\n", req->path.base);
    h2o_lua_handle_request(req);
    return 0;
}

static int my_h2o_c_handler(h2o_handler_t *self, h2o_req_t *req)
{
    static h2o_generator_t generator = { NULL, NULL };
    //printf("hello_handler : %s : %d\n", req->method.base, (uint)req->method.len);
    if (! h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
        return -1;
    //printf("===Request path = %s\n", req->path.base);
    size_t body_size = 1024;
    h2o_iovec_t body;
    body.base = h2o_mem_alloc_pool(&req->pool, body_size);
    req->res.content_length = body.len = snprintf(body.base, body_size, "Hello %.*s", (int)req->path.len, req->path.base);
    req->res.status = 200;
    req->res.reason = "OK";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain"));
    h2o_start_response(req, &generator);
    h2o_send(req, &body, 1, 1);

    return 0;
}

