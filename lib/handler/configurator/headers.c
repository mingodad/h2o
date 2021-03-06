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
#include <string.h>
#include "h2o.h"
#include "h2o/configurator.h"

struct headers_configurator_t : h2o_configurator_t {
    H2O_VECTOR<h2o_headers_command_t> * cmds, _cmd_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];

    int enter(h2o_configurator_context_t *ctx, yoml_t *node) override;
    int exit(h2o_configurator_context_t *ctx, yoml_t *node) override;
};

static int extract_name(const char *src, size_t len, h2o_iovec_t **_name)
{
    h2o_iovec_t name;
    const h2o_token_t *name_token;

    name = h2o_str_stripws(src, len);
    if (name.len == 0)
        return -1;

    name.strdup(name);
    h2o_strtolower(name);

    if ((name_token = h2o_lookup_token(name.base, name.len)) != NULL) {
        *_name = (h2o_iovec_t *)&name_token->buf;
        h2o_mem_free(name.base);
    } else {
        //memory leak ?
        *_name = h2o_mem_alloc_for<h2o_iovec_t>();
        **_name = name;
    }

    return 0;
}

static int extract_name_value(const char *src, h2o_iovec_t **name, h2o_iovec_t *value)
{
    const char *colon = strchr(src, ':');

    if (colon == NULL)
        return -1;

    if (extract_name(src, colon - src, name) != 0)
        return -1;
    *value = h2o_str_stripws(colon + 1, strlen(colon + 1));
    value->strdup(*value);

    return 0;
}

static int add_cmd(h2o_configurator_command_t *cmd, yoml_t *node, int cmd_id, h2o_iovec_t *name, h2o_iovec_t value)
{
    auto self = (headers_configurator_t *)cmd->configurator;

    if (h2o_iovec_is_token(name)) {
        auto token = (const h2o_token_t *)name;
        if (h2o_headers_is_prohibited_name(token)) {
            cmd->errprintf(node, "the named header cannot be rewritten");
            return -1;
        }
    }

    self->cmds->push_back(NULL, {cmd_id, name, value});
    return 0;
}

static int on_config_header_2arg(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, int cmd_id, yoml_t *node)
{
    h2o_iovec_t *name, value;

    if (extract_name_value(node->data.scalar, &name, &value) != 0) {
        cmd->errprintf(node, "failed to parse the value; should be in form of `name: value`");
        return -1;
    }
    if (add_cmd(cmd, node, cmd_id, name, value) != 0)
    {
        if(!h2o_iovec_is_token(name)) h2o_mem_free(name->base);
        h2o_mem_free(value.base);
        return -1;
    }
    return 0;
}

#define DEFINE_2ARG(fn, cmd_id)                                                                                                    \
    static int fn(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)                                  \
    {                                                                                                                              \
        return on_config_header_2arg(cmd, ctx, cmd_id, node);                                                                      \
    }

DEFINE_2ARG(on_config_header_add, H2O_HEADERS_CMD_ADD)
DEFINE_2ARG(on_config_header_append, H2O_HEADERS_CMD_APPEND)
DEFINE_2ARG(on_config_header_merge, H2O_HEADERS_CMD_MERGE)
DEFINE_2ARG(on_config_header_set, H2O_HEADERS_CMD_SET)
DEFINE_2ARG(on_config_header_setifempty, H2O_HEADERS_CMD_SETIFEMPTY)

#undef DEFINE_2ARG

static int on_config_header_unset(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    h2o_iovec_t *name;

    if (extract_name(node->data.scalar, strlen(node->data.scalar), &name) != 0) {
        cmd->errprintf(node, "invalid header name");
        return -1;
    }
    if (add_cmd(cmd, node, H2O_HEADERS_CMD_UNSET, name, {}) != 0)
    {
        if(!h2o_iovec_is_token(name)) h2o_mem_free(name->base);
        return -1;
    }
    return 0;
}

int headers_configurator_t::enter(h2o_configurator_context_t *ctx, yoml_t *node)
{
    this->cmds[1].assign(NULL, &this->cmds[0]);
    ++this->cmds;
    return 0;
}

int headers_configurator_t::exit(h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (ctx->pathconf != NULL && this->cmds->size != 0) {
        this->cmds->push_back(NULL, ((h2o_headers_command_t){H2O_HEADERS_CMD_NULL}));
        h2o_headers_register(ctx->pathconf, this->cmds->entries);
    } else {
        h2o_mem_free(this->cmds->entries);
    }
    h2o_clearmem(this->cmds);

    --this->cmds;
    return 0;
}

void h2o_headers_register_configurator(h2o_globalconf_t *conf)
{
    auto c = conf->configurator_create<headers_configurator_t>();

#define DEFINE_CMD(name, cb) \
    c->define_command(name, \
        H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR, cb)
    DEFINE_CMD("header.add", on_config_header_add);
    DEFINE_CMD("header.append", on_config_header_append);
    DEFINE_CMD("header.merge", on_config_header_merge);
    DEFINE_CMD("header.set", on_config_header_set);
    DEFINE_CMD("header.setifempty", on_config_header_setifempty);
    DEFINE_CMD("header.unset", on_config_header_unset);
#undef DEFINE_CMD

    c->cmds = c->_cmd_stack;
}
