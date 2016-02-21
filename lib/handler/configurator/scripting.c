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

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "h2o/scripting.h"

int h2o_scripting_configurator_t::on_config_scripting_handler(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (h2o_scripting_configurator_t *)cmd->configurator;

    /* set source */
    self->vars->source.strdup(NULL, node->data.scalar, SIZE_MAX);
    self->vars->path = node->filename;
    self->vars->lineno = (int)node->line;

    /* check if there is any error in source */
    char errbuf[1024];
    if (self->compile_test(self->vars, errbuf)) {
        cmd->errprintf(node, "%s compile error:%s", self->scripting_language_name, errbuf);
        goto Error;
    }

    /* register */
    self->pathconf_register(ctx->pathconf, self->vars);

    return 0;

Error:
    h2o_mem_free(self->vars->source.base);
    return -1;
}

int h2o_scripting_configurator_t::on_config_scripting_handler_file(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (h2o_scripting_configurator_t *)cmd->configurator;
    FILE *fp = NULL;
    h2o_iovec_t buf = {};
    int ret = -1;
    const size_t read_size = 65536;

    /* open and read file */
    if ((fp = fopen(node->data.scalar, "rt")) == NULL) {
        cmd->errprintf(node, "failed to open file: %s:%s",
                node->data.scalar, strerror(errno));
        goto Exit;
    }
    while (!feof(fp)) {
        buf.base = h2o_mem_realloc_for<char>(buf.base, buf.len + read_size);
        buf.len += fread(buf.base, 1, read_size, fp);
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
    if (self->compile_test(self->vars, errbuf)) {
        cmd->errprintf(node, "failed to compile file:%s:%s",
                node->data.scalar, errbuf);
        goto Exit;
    }

    /* register */
    self->pathconf_register(ctx->pathconf, self->vars);

    ret = 0;

Exit:
    if (fp != NULL)
        fclose(fp);
    if (buf.base != NULL)
        h2o_mem_free(buf.base);
    return ret;
}

int h2o_scripting_configurator_t::on_config_scripting_handler_path(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    cmd->errprintf(node, "the command has been removed; see https://github.com/h2o/h2o/pull/467");
    return -1;
}

int h2o_scripting_configurator_t::enter(h2o_configurator_context_t *ctx, yoml_t *node)
{
    memcpy(this->vars + 1, this->vars, sizeof(*this->vars));
    ++this->vars;
    return 0;
}

int h2o_scripting_configurator_t::exit(h2o_configurator_context_t *ctx, yoml_t *node)
{
    /* free if the to-be-exitted frame level contains a different source */
    if (this->vars[-1].source.base != this->vars[-1].source.base)
        h2o_mem_free(this->vars->source.base);

    --this->vars;
    return 0;
}


void h2o_scripting_configurator_t::register_configurator(h2o_scripting_configurator_t *c, h2o_globalconf_t *conf)
{
    char buf[256];
    c->vars = c->_vars_stack;

    #define CMD_NAME(cn) snprintf(buf, sizeof(buf), "%s." cn, c->scripting_language_name)

    auto cf = h2o_CONFIGURATOR_FLAG(H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_DEFERRED);
    CMD_NAME("handler_path");
    c->define_command(buf, cf, h2o_scripting_configurator_t::on_config_scripting_handler_path);

    cf = h2o_CONFIGURATOR_FLAG(cf | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR);
    CMD_NAME("handler");
    c->define_command(buf, cf, h2o_scripting_configurator_t::on_config_scripting_handler);
    CMD_NAME("handler-file");
    c->define_command(buf, cf, h2o_scripting_configurator_t::on_config_scripting_handler_file);
    #undef CMD_NAME
}

void h2o_scripting_handler_t::dispose(h2o_base_handler_t *_handler)
{
    auto handler = (h2o_scripting_handler_t *)_handler;

    h2o_mem_free(handler->config.source.base);
    h2o_mem_free(handler->config.path);
    h2o_mem_free(handler);
}
