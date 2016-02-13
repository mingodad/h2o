/*
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
#include "h2o.h"
#include "h2o/configurator.h"
#include "h2o/mruby_.h"

struct mruby_configurator_t : h2o_configurator_t {
    h2o_mruby_config_vars_t *vars;
    h2o_mruby_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static int compile_test(h2o_mruby_config_vars_t *config, char *errbuf)
{
    mrb_state *mrb;

    if ((mrb = mrb_open()) == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_MRUBY_MODULE_NAME);
        abort();
    }
    int ok = !mrb_nil_p(h2o_mruby_compile_code(mrb, config, errbuf));
    mrb_close(mrb);

    return ok;
}

static int on_config_mruby_handler(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (mruby_configurator_t *)cmd->configurator;

    /* set source */
    self->vars->source.strdup(NULL, node->data.scalar, SIZE_MAX);
    self->vars->path = node->filename;
    self->vars->lineno = (int)node->line;

    /* check if there is any error in source */
    char errbuf[1024];
    if (!compile_test(self->vars, errbuf)) {
        cmd->errprintf(node, "ruby compile error:%s", errbuf);
        return -1;
    }

    /* register */
    h2o_mruby_register(ctx->pathconf, self->vars);

    return 0;
}

static int on_config_mruby_handler_file(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (mruby_configurator_t *)cmd->configurator;
    FILE *fp = NULL;
    h2o_iovec_t buf = {};
    int ret = -1;

    /* open and read file */
    if ((fp = fopen(node->data.scalar, "rt")) == NULL) {
        cmd->errprintf(node, "failed to open file: %s:%s",
                node->data.scalar, strerror(errno));
        goto Exit;
    }
    while (!feof(fp)) {
        buf.base = h2o_mem_realloc_for<char>(buf.base, buf.len + 65536);
        buf.len += fread(buf.base, 1, 65536, fp);
        if (ferror(fp)) {
            cmd->errprintf(node,
                    "I/O error occurred while reading file:%s:%s",
                    node->data.scalar, strerror(errno));
            goto Exit;
        }
    }

    /* set source */
    self->vars->source = buf;
    buf.base = NULL;
    self->vars->path = node->data.scalar; /* the value is retained until the end of the configuration phase */
    self->vars->lineno = 0;

    /* check if there is any error in source */
    char errbuf[1024];
    if (!compile_test(self->vars, errbuf)) {
        cmd->errprintf(node, "failed to compile file:%s:%s",
                node->data.scalar, errbuf);
        goto Exit;
    }

    /* register */
    h2o_mruby_register(ctx->pathconf, self->vars);

    ret = 0;

Exit:
    if (fp != NULL)
        fclose(fp);
    if (buf.base != NULL)
        h2o_mem_free(buf.base);
    return ret;
}

static int on_config_mruby_handler_path(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    cmd->errprintf(node, "the command has been removed; see https://github.com/h2o/h2o/pull/467");
    return -1;
}

static int on_config_enter(h2o_configurator_t *_self,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (mruby_configurator_t *)_self;

    memcpy(self->vars + 1, self->vars, sizeof(*self->vars));
    ++self->vars;
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (mruby_configurator_t *)_self;

    /* free if the to-be-exitted frame level contains a different source */
    if (self->vars[-1].source.base != self->vars[-1].source.base)
        h2o_mem_free(self->vars->source.base);

    --self->vars;
    return 0;
}

void h2o_mruby_register_configurator(h2o_globalconf_t *conf)
{
    auto c = conf->configurator_create<mruby_configurator_t>();

    c->vars = c->_vars_stack;
    c->enter = on_config_enter;
    c->exit = on_config_exit;

    auto cf = h2o_CONFIGURATOR_FLAG(H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_DEFERRED);
    c->define_command("mruby.handler_path", cf, on_config_mruby_handler_path);

    cf = h2o_CONFIGURATOR_FLAG(cf | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR);
    c->define_command("mruby.handler", cf, on_config_mruby_handler);
    c->define_command("mruby.handler-file", cf, on_config_mruby_handler_file);
}
