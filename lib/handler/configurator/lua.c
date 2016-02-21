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

struct lua_configurator_t : h2o_scripting_configurator_t {

    lua_configurator_t():h2o_scripting_configurator_t("lua"){}

    int compile_test(h2o_scripting_config_vars_t *config, char *errbuf) override;

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

int h2o_lua_compile_code(lua_State *L, h2o_scripting_config_vars_t *config, char *errbuf)
{
    set_h2o_root(L);

    /* parse */
    int result = luaL_loadbuffer(L, config->source.base, config->source.len, config->path);
    if (result && !lua_isnil(L, -1)) {
        const char *msg = lua_tostring(L, -1);
        if (msg == NULL) msg = "(error object is not a string)";
        fprintf(stderr, "%s: %s\n", H2O_LUA_MODULE_NAME, msg);
         lua_pop(L, 1);
        goto Exit;
    }

Exit:
    return result;
}

int lua_configurator_t::compile_test(h2o_scripting_config_vars_t *config, char *errbuf)
{
    lua_State *L = lua_open();

    if (L == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_LUA_MODULE_NAME);
        abort();
    }
    int ok = h2o_lua_compile_code(L, config, errbuf);
    lua_close(L);

    return ok;
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    int result = 0;
    return result;
}

h2o_lua_handler_t *h2o_lua_register(h2o_pathconf_t *pathconf, h2o_scripting_config_vars_t *vars)
{
    auto handler = pathconf->create_handler<h2o_lua_handler_t>();

    handler->on_req = on_req;
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
    auto handler_ctx = h2o_mem_alloc_for<h2o_lua_context_t>();

    handler_ctx->handler = this;

    /* init mruby in every thread */
    if ((handler_ctx->L = lua_open()) == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_LUA_MODULE_NAME);
        abort();
    }

    /* compile code (must be done for each thread) */
    int rc = h2o_lua_compile_code(handler_ctx->L, &this->config, NULL);

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
