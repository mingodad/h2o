/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
#include "h2o.h"
#include "h2o/configurator.h"

struct gzip_config_vars_t {
    int on;
};

struct gzip_configurator_t : h2o_configurator_t {
    struct gzip_config_vars_t *vars, _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
} ;

static int on_config_gzip(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (gzip_configurator_t *)cmd->configurator;

    if ((self->vars->on = (int)cmd->get_one_of(node, "OFF,ON")) == -1)
        return -1;
    return 0;
}

static int on_config_enter(h2o_configurator_t *configurator, h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (gzip_configurator_t *)configurator;

    ++self->vars;
    self->vars[0] = self->vars[-1];
    return 0;
}

static int on_config_exit(h2o_configurator_t *configurator, h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (gzip_configurator_t *)configurator;

    if (ctx->pathconf != NULL && self->vars->on)
        h2o_gzip_register(ctx->pathconf);

    --self->vars;
    return 0;
}

void h2o_gzip_register_configurator(h2o_globalconf_t *conf)
{
    auto c = conf->configurator_create<gzip_configurator_t>();

    c->enter = on_config_enter;
    c->exit = on_config_exit;
    c->define_command("gzip", H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_gzip);
    c->vars = c->_vars_stack;
}
