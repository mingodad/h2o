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
#ifndef H20_SQUILU_H
#define H20_SQUILU_H

#include "h2o/scripting.h"
#include "squirrel.h"

#define H2O_SQUILU_MODULE_NAME "h2o_squilu"

struct h2o_squilu_handler_t : h2o_scripting_handler_t {
    typedef h2o_scripting_handler_t super;

    h2o_squilu_handler_t():h2o_scripting_handler_t() {}

    void on_context_init(h2o_context_t *ctx) override;
    void on_context_dispose(h2o_context_t *ctx) override;
    int compile_code(void *ctx, h2o_scripting_config_vars_t *config_var) override;
    int reload_scripting_file(void *ctx, h2o_scripting_config_vars_t *config_var) override;
};

struct h2o_squilu_context_t {
    h2o_squilu_handler_t *handler;
    HSQUIRRELVM sq;
};

struct h2o_squilu_generator_t : h2o_generator_t {
    //h2o_req_t *req; /* becomes NULL once the underlying connection gets terminated */
    HSQUIRRELVM sq;
    HSQOBJECT /*h2o_generator,*/
        h2o_generator_squilu_cb_proceed,
        h2o_generator_squilu_cb_data,
        h2o_generator_squilu_cb_stop;
};

/* handler/squilu.c */
h2o_squilu_handler_t *h2o_squilu_register(h2o_pathconf_t *pathconf, h2o_scripting_config_vars_t *vars);
void h2o_squilu_register_configurator(h2o_globalconf_t *conf);

#endif

