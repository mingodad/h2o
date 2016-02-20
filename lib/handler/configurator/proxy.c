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
#include <inttypes.h>
#include "h2o.h"
#include "h2o/configurator.h"

struct proxy_configurator_t : h2o_configurator_t {
    h2o_proxy_config_vars_t *vars;
    h2o_proxy_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];

    int enter(h2o_configurator_context_t *ctx, yoml_t *node) override;
    int exit(h2o_configurator_context_t *ctx, yoml_t *node) override;
};

static int on_config_websocket_timeout(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (proxy_configurator_t *)cmd->configurator;
    return cmd->scanf(node, "%" PRIu64,
            &self->vars->websocket.timeout);
}

static int on_config_websocket(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    ssize_t ret = cmd->get_one_of(node, "OFF,ON");
    if (ret == -1)
        return -1;
    ((proxy_configurator_t *)cmd->configurator)->vars->websocket.enabled = (int)ret;
    return 0;
}

static int on_config_timeout_io(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (proxy_configurator_t *)cmd->configurator;
    return cmd->scanf(node, "%" PRIu64, &self->vars->io_timeout);
}

static int on_config_timeout_keepalive(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (proxy_configurator_t *)cmd->configurator;
    return cmd->scanf(node, "%" PRIu64,
            &self->vars->keepalive_timeout);
}

static int on_config_preserve_host(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    ssize_t ret = cmd->get_one_of(node, "OFF,ON");
    if (ret == -1)
        return -1;
    ((proxy_configurator_t *)cmd->configurator)->vars->preserve_host = (int)ret;
    return 0;
}

static int on_config_reverse_url(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (proxy_configurator_t *)cmd->configurator;
    h2o_url_t parsed;

    if (parsed.parse(node->data.scalar, SIZE_MAX) != 0) {
        cmd->errprintf(node, "failed to parse URL: %s\n",
                node->data.scalar);
        return -1;
    }
    if (parsed.scheme != &H2O_URL_SCHEME_HTTP) {
        cmd->errprintf(node, "only HTTP URLs are supported");
        return -1;
    }
    /* register */
    h2o_proxy_register_reverse_proxy(ctx->pathconf, &parsed, self->vars);

    return 0;
}

int proxy_configurator_t::enter(h2o_configurator_context_t *ctx, yoml_t *node)
{
    memcpy(this->vars + 1, this->vars, sizeof(*this->vars));
    ++this->vars;
    return 0;
}

int proxy_configurator_t::exit(h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (ctx->pathconf == NULL && ctx->hostconf == NULL) {
        /* is global conf */
        ctx->globalconf->proxy.io_timeout = this->vars->io_timeout;
    }

    --this->vars;
    return 0;
}

void h2o_proxy_register_configurator(h2o_globalconf_t *conf)
{
    auto c = conf->configurator_create<proxy_configurator_t>();

    /* set default vars */
    c->vars = c->_vars_stack;
    c->vars->io_timeout = H2O_DEFAULT_PROXY_IO_TIMEOUT;
    c->vars->keepalive_timeout = 2000;
    /* have websocket proxying disabled by default; until it becomes non-experimental */
    c->vars->websocket.enabled = 0;
    c->vars->websocket.timeout = H2O_DEFAULT_PROXY_WEBSOCKET_TIMEOUT;

    /* setup handlers */
    c->define_command("proxy.reverse.url",
        H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR
            | H2O_CONFIGURATOR_FLAG_DEFERRED, on_config_reverse_url);

    auto cf = h2o_CONFIGURATOR_FLAG(H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR);
    c->define_command("proxy.preserve-host", cf, on_config_preserve_host);
    c->define_command("proxy.timeout.io", cf, on_config_timeout_io);
    c->define_command("proxy.timeout.keepalive", cf, on_config_timeout_keepalive);
    c->define_command("proxy.websocket", cf, on_config_websocket);
    c->define_command("proxy.websocket.timeout", cf, on_config_websocket_timeout);
}
