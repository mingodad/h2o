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
#ifndef H20_HELLO_H
#define H20_HELLO_H

#include "h2o.h"
#include "h2o/configurator.h"

#define H2O_HELLO_MODULE_NAME "h2o_hello"

struct h2o_hello_configurator_t : h2o_configurator_t {
};

struct h2o_hello_handler_t : h2o_handler_t {
};

struct h2o_hello_generator_t : h2o_generator_t {
    h2o_req_t *req; /* becomes NULL once the underlying connection gets terminated */
};

/* handler/configurator/hello.c */
void h2o_hello_register_configurator(h2o_globalconf_t *conf);

#endif //H20_HELLO_H

