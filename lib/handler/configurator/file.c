/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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

struct h2o_file_config_vars_t {
    const char **index_files;
    int flags;
};

#define FILE_VARS(x)((h2o_file_configurator_t *)cmd->configurator)->vars->x

struct h2o_file_configurator_t : h2o_configurator_t {
    h2o_file_config_vars_t *vars;
    h2o_file_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];

    int enter(h2o_configurator_context_t *ctx, yoml_t *node) override;
    int exit(h2o_configurator_context_t *ctx, yoml_t *node) override;
};

static int on_config_dir(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (h2o_file_configurator_t *)cmd->configurator;

    h2o_file_register(ctx->pathconf, node->data.scalar, self->vars->index_files, *ctx->mimemap, self->vars->flags);
    return 0;
}

static int on_config_index(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (h2o_file_configurator_t *)cmd->configurator;
    size_t i;

    h2o_mem_free(self->vars->index_files);
    self->vars->index_files = h2o_mem_alloc_for<const char*>(node->data.sequence.size + 1);
    for (i = 0; i != node->data.sequence.size; ++i) {
        yoml_t *element = node->data.sequence.elements[i];
        if (element->type != YOML_TYPE_SCALAR) {
            cmd->errprintf(element, "argument must be a sequence of scalars");
            return -1;
        }
        self->vars->index_files[i] = element->data.scalar;
    }
    self->vars->index_files[i] = NULL;

    return 0;
}

static void on_config_etag(h2o_configurator_command_t *cmd, bool result)
{
    if (result) FILE_VARS(flags) &= ~H2O_FILE_FLAG_NO_ETAG; //on
    else FILE_VARS(flags) |= H2O_FILE_FLAG_NO_ETAG; //off
}

static void on_config_send_gzip(h2o_configurator_command_t *cmd, bool result)
{
    if (result) FILE_VARS(flags) |= H2O_FILE_FLAG_SEND_GZIP; //on
    else FILE_VARS(flags) &= ~H2O_FILE_FLAG_SEND_GZIP; //off
}

static void on_config_dir_listing(h2o_configurator_command_t *cmd, bool result)
{
    if (result) FILE_VARS(flags) |= H2O_FILE_FLAG_DIR_LISTING; //on
    else FILE_VARS(flags) &= ~H2O_FILE_FLAG_DIR_LISTING; //off
}

static const char **dup_strlist(const char **s)
{
    size_t i;
    const char **ret;

    for (i = 0; s[i] != NULL; ++i)
        ;
    ret = h2o_mem_alloc_for<const char*>(i + 1);
    for (i = 0; s[i] != NULL; ++i)
        ret[i] = s[i];
    ret[i] = NULL;

    return ret;
}

int h2o_file_configurator_t::enter(h2o_configurator_context_t *ctx, yoml_t *node)
{
    ++this->vars;
    this->vars[0].index_files = dup_strlist(this->vars[-1].index_files);
    this->vars[0].flags = this->vars[-1].flags;
    return 0;
}

int h2o_file_configurator_t::exit(h2o_configurator_context_t *ctx, yoml_t *node)
{
    h2o_mem_free(this->vars->index_files);
    --this->vars;
    return 0;
}

void h2o_file_register_configurator(h2o_globalconf_t *globalconf)
{
    auto self = globalconf->configurator_create<h2o_file_configurator_t>();

    self->vars = self->_vars_stack;
    self->vars->index_files = h2o_file_default_index_files;

    self->define_command("file.dir", H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR |
                                                                  H2O_CONFIGURATOR_FLAG_DEFERRED,
                                    on_config_dir);

    auto cf = h2o_CONFIGURATOR_FLAG(H2O_CONFIGURATOR_FLAG_ALL_LEVELS & ~H2O_CONFIGURATOR_FLAG_EXTENSION);
    self->define_command("file.index", cf | H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE,
                                    on_config_index);

    cf = h2o_CONFIGURATOR_FLAG(cf | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR);
    self->define_command("file.etag", cf, on_config_etag);
    self->define_command("file.send-gzip", cf, on_config_send_gzip);
    self->define_command("file.dirlisting", cf, on_config_dir_listing);
}
