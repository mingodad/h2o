/*
 * Copyright (c) 2015 Daisuke Maki, DeNA Co., Ltd., Kazuho Oku
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
#include <inttypes.h>
#include "h2o.h"
#include "h2o/configurator.h"

struct config_t {
    int enabled;
};

struct reproxy_configurator_t : h2o_configurator_t {
    struct config_t *vars, _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];

    int enter(h2o_configurator_context_t *ctx, yoml_t *node) override;
    int exit(h2o_configurator_context_t *ctx, yoml_t *node) override;
};

static int on_config_reproxy(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    ssize_t ret = cmd->get_one_of(node, "OFF,ON");
    if (ret == -1)
        return -1;
    ((reproxy_configurator_t *)cmd->configurator)->vars->enabled = (int)ret;
    return 0;
}

int reproxy_configurator_t::enter(h2o_configurator_context_t *ctx, yoml_t *node)
{
    this->vars[1] = this->vars[0];
    ++this->vars;
    return 0;
}

int reproxy_configurator_t::exit(h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (ctx->pathconf != NULL && this->vars->enabled != 0)
        h2o_reproxy_register(ctx->pathconf);

    --this->vars;
    return 0;
}

void h2o_reproxy_register_configurator(h2o_globalconf_t *conf)
{
    auto c = conf->configurator_create<reproxy_configurator_t>();

    /* set default vars */
    c->vars = c->_vars_stack;

    /* reproxy: ON | OFF */
    c->define_command("reproxy",
        H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_reproxy);
}
