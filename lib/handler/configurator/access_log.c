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

typedef H2O_VECTOR<h2o_access_log_filehandle_t *> st_h2o_access_log_filehandle_vector_t;

struct h2o_access_log_configurator_t : h2o_configurator_t {
    st_h2o_access_log_filehandle_vector_t *handles;
    st_h2o_access_log_filehandle_vector_t _handles_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    h2o_access_log_configurator_t *self = (h2o_access_log_configurator_t *)cmd->configurator;
    const char *path, *fmt = NULL;
    h2o_access_log_filehandle_t *fh;

    switch (node->type) {
    case YOML_TYPE_SCALAR:
        path = node->data.scalar;
        break;
    case YOML_TYPE_MAPPING: {
        yoml_t *t;
        /* get path */
        if ((t = yoml_get(node, "path")) == NULL) {
            cmd->errprintf(node, "could not find mandatory key `path`");
            return -1;
        }
        if (t->type != YOML_TYPE_SCALAR) {
            cmd->errprintf(t, "`path` must be scalar");
            return -1;
        }
        path = t->data.scalar;
        /* get format */
        if ((t = yoml_get(node, "format")) != NULL) {
            if (t->type != YOML_TYPE_SCALAR) {
                cmd->errprintf(t, "`format` must be a scalar");
                return -1;
            }
            fmt = t->data.scalar;
        }
    } break;
    default:
        cmd->errprintf(node, "node must be a scalar or a mapping");
        return -1;
    }

    if (!ctx->dry_run) {
        if ((fh = h2o_access_log_open_handle(path, fmt)) == NULL)
            return -1;
        self->handles->push_back(NULL, fh);
    }

    return 0;
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    h2o_access_log_configurator_t *self = (h2o_access_log_configurator_t *)_self;
    size_t i;

    /* push the stack pointer */
    ++self->handles;

    /* link the handles */
    h2o_clearmem(self->handles);
    self->handles->reserve_more(NULL, 1);
    for (i = 0; i != self->handles[-1].size; ++i) {
        h2o_access_log_filehandle_t *fh = self->handles[-1][i];
        self->handles[0][self->handles[0].size++] = fh;
        h2o_mem_addref_shared(fh);
    }

    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    h2o_access_log_configurator_t *self = (h2o_access_log_configurator_t *)_self;
    size_t i;

    /* register all handles, and decref them */
    for (i = 0; i != self->handles->size; ++i) {
        h2o_access_log_filehandle_t *fh = self->handles->entries[i];
        if (ctx->pathconf != NULL)
            h2o_access_log_register(ctx->pathconf, fh);
        h2o_mem_release_shared(fh);
    }
    /* free the vector */
    h2o_mem_free(self->handles->entries);

    /* pop the stack pointer */
    --self->handles;

    return 0;
}

void h2o_access_log_register_configurator(h2o_globalconf_t *conf)
{
    auto self = conf->configurator_create<h2o_access_log_configurator_t>();

    self->enter = on_config_enter;
    self->exit = on_config_exit;
    self->handles = self->_handles_stack;

    self->define_command("access-log", H2O_CONFIGURATOR_FLAG_ALL_LEVELS, on_config);
}
