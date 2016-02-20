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
#include <stdio.h>
#include <string.h>
#include "h2o.h"
#include "h2o/configurator.h"

struct expires_configurator_t : h2o_configurator_t {
    h2o_expires_args_t **args;
    h2o_expires_args_t *_args_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];

    int enter(h2o_configurator_context_t *ctx, yoml_t *node) override;
    int exit(h2o_configurator_context_t *ctx, yoml_t *node) override;
};

static int on_config_expires(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (expires_configurator_t *)cmd->configurator;
    uint64_t value;
    char unit[32];

    if (isScalar(node, "OFF")) {
        h2o_mem_free(*self->args);
        *self->args = NULL;
    } else if (sscanf(node->data.scalar, "%" PRIu64 " %31s", &value, unit) == 2) {
        /* convert value to seconds depending on the unit */
        if (strncasecmp(unit, H2O_STRLIT("second")) == 0) {
            /* ok */
        } else if (strncasecmp(unit, H2O_STRLIT("minute")) == 0) {
            value *= 60;
        } else if (strncasecmp(unit, H2O_STRLIT("hour")) == 0) {
            value *= 60 * 60;
        } else if (strncasecmp(unit, H2O_STRLIT("day")) == 0) {
            value *= 24 * 60 * 60;
        } else if (strncasecmp(unit, H2O_STRLIT("month")) == 0) {
            value *= 30 * 60 * 60;
        } else if (strncasecmp(unit, H2O_STRLIT("year")) == 0) {
            value *= 365 * 30 * 60 * 60;
        } else {
            /* TODO add support for H2O_EXPIRES_MODE_MAX_ABSOLUTE that sets the Expires header? */
            cmd->errprintf(node, "unknown unit:`%s` (see --help)", unit);
            return -1;
        }
        /* save the value */
        if (*self->args == NULL)
            *self->args = h2o_mem_alloc_for<h2o_expires_args_t>();
        (*self->args)->mode = H2O_EXPIRES_MODE_MAX_AGE;
        (*self->args)->data.max_age = value;
    } else {
        cmd->errprintf(node,
                                   "failed to parse the value, should be in form of: `<number> <unit>` or `OFF` (see --help)");
        return -1;
    }

    return 0;
}

int expires_configurator_t::enter(h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (this->args[0] != NULL) {
        /* duplicate */
        assert(this->args[0]->mode == H2O_EXPIRES_MODE_MAX_AGE);
        this->args[1] = h2o_mem_alloc_for<h2o_expires_args_t>();
        *this->args[1] = *this->args[0];
    } else {
        this->args[1] = NULL;
    }
    ++this->args;
    return 0;
}

int expires_configurator_t::exit(h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (*this->args != NULL) {
        /* setup */
        if (ctx->pathconf != NULL) {
            h2o_expires_register(ctx->pathconf, *this->args);
        }
        /* destruct */
        assert((*this->args)->mode == H2O_EXPIRES_MODE_MAX_AGE);
        h2o_mem_free(*this->args);
        *this->args = NULL;
    }

    --this->args;
    return 0;
}

void h2o_expires_register_configurator(h2o_globalconf_t *conf)
{
    auto c = conf->configurator_create<expires_configurator_t>();

    /* set default vars */
    c->args = c->_args_stack;

    /* setup handlers */
    c->define_command("expires",
            H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
            on_config_expires);
}
