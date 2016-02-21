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
#include "h2o/mruby_.h"

struct mruby_configurator_t : h2o_scripting_configurator_t {

    mruby_configurator_t():h2o_scripting_configurator_t("mruby"){}

    int compile_test(h2o_scripting_config_vars_t *config, char *errbuf) override;

    h2o_scripting_handler_t *pathconf_register(h2o_pathconf_t *pathconf, h2o_scripting_config_vars_t *vars) override
    {
        return (h2o_scripting_handler_t*)h2o_mruby_register(pathconf, vars);
    }
};

int mruby_configurator_t::compile_test(h2o_scripting_config_vars_t *config, char *errbuf)
{
    mrb_state *mrb;

    if ((mrb = mrb_open()) == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_MRUBY_MODULE_NAME);
        abort();
    }
    int ok = mrb_nil_p(h2o_mruby_compile_code(mrb, config, errbuf));
    mrb_close(mrb);

    return ok;
}

void h2o_mruby_register_configurator(h2o_globalconf_t *conf)
{
    auto c = conf->configurator_create<mruby_configurator_t>();
    c->register_configurator(c, conf);
}
