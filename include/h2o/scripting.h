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
#ifndef H20_SCRIPTING_H
#define H20_SCRIPTING_H

#include "h2o.h"
#include "h2o/configurator.h"

struct h2o_scripting_config_vars_t {
    h2o_iovec_t source;
    char *path;
    int lineno;
};

struct h2o_scripting_handler_t : h2o_handler_t {
    h2o_scripting_config_vars_t config;

    h2o_scripting_handler_t(): config({}) {}
};

struct h2o_scripting_configurator_t : h2o_configurator_t {
    h2o_scripting_config_vars_t *vars;
    h2o_scripting_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
    const char *scripting_language_name;

    h2o_scripting_configurator_t(const char *language_name):
        h2o_configurator_t(),scripting_language_name(language_name){}

    int enter(h2o_configurator_context_t *ctx, yoml_t *node) override;
    int exit(h2o_configurator_context_t *ctx, yoml_t *node) override;

    virtual int compile_test(h2o_scripting_config_vars_t *config, char *errbuf) = 0;
    virtual h2o_scripting_handler_t *pathconf_register(h2o_pathconf_t *pathconf, h2o_scripting_config_vars_t *vars) = 0;

    static int on_config_scripting_handler(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node);
    static int on_config_scripting_handler_file(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node);
    static int on_config_scripting_handler_path(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node);

    static void register_configurator(h2o_scripting_configurator_t *c, h2o_globalconf_t *conf);
};

#endif // H20_SCRIPTING_H
